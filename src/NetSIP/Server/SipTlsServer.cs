using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetSIP.Common;
using NetSIP.Message;
using NetSIP.Parser;
using NetSIP.Request;
using NetSIP.Response;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace NetSIP.Server
{
    /// <summary>
    /// A bounded, cancellation-aware SIP over TLS server.
    /// </summary>
    public sealed class SipTlsServer : IAsyncDisposable
    {
        /// <summary>
        /// Validated server configuration.
        /// </summary>
        private readonly SipTlsServerOptions _options;

        /// <summary>
        /// Application handler invoked serially for each message on a connection.
        /// </summary>
        private readonly ISipRequestHandler _handler;

        /// <summary>
        /// Structured server logger.
        /// </summary>
        private readonly ILogger _logger;

        /// <summary>
        /// Cancellation source shared by the accept loop and active connections.
        /// </summary>
        private readonly CancellationTokenSource _lifetime = new();

        /// <summary>
        /// Admission limit held for each accepted connection task.
        /// </summary>
        private readonly SemaphoreSlim _connectionSlots;

        /// <summary>
        /// Active connection tasks awaited during graceful shutdown.
        /// </summary>
        private readonly ConcurrentDictionary<long, Task> _connections = new();

        /// <summary>
        /// The listening socket.
        /// </summary>
        private Socket? _listener;

        /// <summary>
        /// The task running the accept loop.
        /// </summary>
        private Task? _acceptLoop;

        /// <summary>
        /// Monotonic diagnostic connection identifier.
        /// </summary>
        private long _nextConnectionId;

        /// <summary>
        /// Lifecycle state: 0 = not started, 1 = started, 2 = stopping or stopped.
        /// </summary>
        private int _state;

        /// <summary>
        /// Initializes a new instance of the <see cref="SipTlsServer"/> class.
        /// </summary>
        /// <param name="options">The server configuration options.</param>
        /// <param name="handler">The request handler.</param>
        /// <param name="logger">Optional logger for server operations.</param>
        public SipTlsServer(
            SipTlsServerOptions options,
            ISipRequestHandler handler,
            ILogger<SipTlsServer>? logger = null)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(handler);
            options.Validate();

            _options = options;
            _handler = handler;
            _logger = logger ?? NullLogger<SipTlsServer>.Instance;
            _connectionSlots = new SemaphoreSlim(options.MaxConcurrentConnections);
        }

        /// <summary>
        /// Gets the actual local endpoint after startup, including an assigned ephemeral port.
        /// Returns <see langword="null"/> before startup succeeds.
        /// </summary>
        public IPEndPoint? BoundEndPoint { get; private set; }

        /// <summary>
        /// Starts the server and begins accepting connections.
        /// </summary>
        /// <param name="cancellationToken">
        /// A token that can cancel before startup begins. Use <see cref="StopAsync"/> for shutdown.
        /// </param>
        /// <returns>A completed task if startup succeeds.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the server has already been started.</exception>
        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            {
                throw new InvalidOperationException("The server has already been started.");
            }

            Socket listener = new(
                _options.ListenEndPoint.AddressFamily,
                SocketType.Stream,
                ProtocolType.Tcp);
            try
            {
                listener.NoDelay = true;
                if (_options.ListenEndPoint.Address.Equals(IPAddress.IPv6Any))
                {
                    listener.DualMode = true;
                }

                listener.Bind(_options.ListenEndPoint);
                listener.Listen(_options.Backlog);
                _listener = listener;
                BoundEndPoint = (IPEndPoint)listener.LocalEndPoint!;
                _acceptLoop = AcceptLoopAsync(listener, _lifetime.Token);
                SipLog.ServerStarted(_logger, BoundEndPoint);
                return Task.CompletedTask;
            }
            catch
            {
                // A failed bind/listen attempt leaves the instance eligible for another start.
                listener.Dispose();
                _ = Interlocked.Exchange(ref _state, 0);
                throw;
            }
        }

        /// <summary>
        /// Stops accepting connections, cancels active connection work, and waits for cleanup.
        /// </summary>
        /// <param name="cancellationToken">
        /// Cancels only the wait for shutdown; server cancellation still remains in effect.
        /// </param>
        /// <returns>A task that completes when the server has fully stopped.</returns>
        public async Task StopAsync(CancellationToken cancellationToken = default)
        {
            int priorState = Interlocked.Exchange(ref _state, 2);
            if (priorState == 0)
            {
                return;
            }

            if (priorState == 2)
            {
                SipLog.StopAlreadyInProgress(_logger);
            }
            else
            {
                _lifetime.Cancel();
                _listener?.Dispose();
            }

            if (_acceptLoop is not null)
            {
                await _acceptLoop.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            Task[] activeConnections = [.. _connections.Values];
            if (activeConnections.Length != 0)
            {
                await Task.WhenAll(activeConnections).WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            if (priorState == 1)
            {
                SipLog.ServerStopped(_logger);
            }
        }

        /// <summary>
        /// Disposes the server asynchronously, stopping it if necessary and releasing resources.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            await StopAsync().ConfigureAwait(false);
            _listener?.Dispose();
            _connectionSlots.Dispose();
            _lifetime.Dispose();
        }

        /// <summary>
        /// Accepts connections only after acquiring a bounded admission slot.
        /// </summary>
        private async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await _connectionSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
                    Socket socket;
                    try
                    {
                        socket = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        _ = _connectionSlots.Release();
                        throw;
                    }

                    long connectionId = Interlocked.Increment(ref _nextConnectionId);
                    Task connection = HandleConnectionAsync(connectionId, socket, cancellationToken);
                    _ = _connections.TryAdd(connectionId, connection);

                    // Execute synchronously when possible so slots are returned promptly.
                    _ = connection.ContinueWith(
                        static (_, state) =>
                        {
                            ConnectionCleanup cleanup = (ConnectionCleanup)state!;
                            cleanup.Connections.TryRemove(cleanup.Id, out Task? _);
                            cleanup.Slots.Release();
                        },
                        new ConnectionCleanup(connectionId, _connections, _connectionSlots),
                        CancellationToken.None,
                        TaskContinuationOptions.ExecuteSynchronously,
                        TaskScheduler.Default);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException exception) when (cancellationToken.IsCancellationRequested)
                {
                    SipLog.AcceptStopped(_logger, exception.SocketErrorCode);
                    break;
                }
                catch (SocketException exception)
                {
                    SipLog.AcceptFailed(_logger, exception.SocketErrorCode);
                    try
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                }
            }
        }

        /// <summary>
        /// Owns the socket, negotiates TLS, and runs the framed message loop.
        /// </summary>
        /// <param name="connectionId">Unique identifier for this connection.</param>
        /// <param name="socket">The accepted TCP socket.</param>
        /// <param name="serverCancellationToken">Server shutdown token.</param>
        private async Task HandleConnectionAsync(
            long connectionId,
            Socket socket,
            CancellationToken serverCancellationToken)
        {
            EndPoint? remoteEndPoint = socket.RemoteEndPoint;
            SipLog.ConnectionAccepted(_logger, connectionId, remoteEndPoint);
            socket.NoDelay = true;

            try
            {
                using (socket)
                using (NetworkStream networkStream = new(socket, ownsSocket: false))
                using (SslStream sslStream = new(networkStream, leaveInnerStreamOpen: false))
                {
                    using (CancellationTokenSource handshakeCancellation = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken))
                    {
                        handshakeCancellation.CancelAfter(_options.HandshakeTimeout);
                        SslServerAuthenticationOptions authenticationOptions = new()
                        {
                            ServerCertificate = _options.ServerCertificate,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                            ClientCertificateRequired = false,
                            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                        };
                        await sslStream.AuthenticateAsServerAsync(
                            authenticationOptions,
                            handshakeCancellation.Token).ConfigureAwait(false);
                    }

                    PipeReader reader = PipeReader.Create(
                        sslStream,
                        new StreamPipeReaderOptions(
                            MemoryPool<byte>.Shared,
                            bufferSize: 16 * 1024,
                            minimumReadSize: 4 * 1024,
                            leaveOpen: true));
                    PipeWriter writer = PipeWriter.Create(
                        sslStream,
                        new StreamPipeWriterOptions(
                            MemoryPool<byte>.Shared,
                            minimumBufferSize: 4 * 1024,
                            leaveOpen: true));

                    try
                    {
                        await ProcessMessagesAsync(
                            remoteEndPoint,
                            reader,
                            writer,
                            serverCancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        await reader.CompleteAsync().ConfigureAwait(false);
                        await writer.CompleteAsync().ConfigureAwait(false);
                    }
                }
            }
            catch (AuthenticationException exception)
            {
                SipLog.TlsHandshakeFailed(_logger, connectionId, remoteEndPoint, exception);
            }
            catch (OperationCanceledException) when (serverCancellationToken.IsCancellationRequested)
            {
                SipLog.ConnectionClosed(_logger, connectionId, remoteEndPoint);
            }
            catch (IOException exception)
            {
                SipLog.ConnectionIoFailed(_logger, connectionId, remoteEndPoint, exception);
            }
            catch (SocketException exception)
            {
                SipLog.ConnectionSocketFailed(_logger, connectionId, remoteEndPoint, exception);
            }
            catch (Exception exception)
            {
                SipLog.ConnectionFailed(_logger, connectionId, remoteEndPoint, exception);
            }
        }

        /// <summary>
        /// Frames, parses, and dispatches messages from a TLS-protected connection.
        /// </summary>
        /// <param name="remoteEndPoint">The remote endpoint of the connection.</param>
        /// <param name="reader">Pipeline reader for incoming data.</param>
        /// <param name="pipeWriter">Pipeline writer for responses.</param>
        /// <param name="serverCancellationToken">Server shutdown token.</param>
        private async Task ProcessMessagesAsync(
            EndPoint? remoteEndPoint,
            PipeReader reader,
            PipeWriter pipeWriter,
            CancellationToken serverCancellationToken)
        {
            SipResponseWriter response = new(pipeWriter);
            SipRequestContext context = new(remoteEndPoint, response);
            using CancellationTokenSource readCancellation = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken);
            using CancellationTokenSource handlerCancellation = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken);
            int messageCount = 0;

            while (!serverCancellationToken.IsCancellationRequested)
            {
                ReadResult readResult;
                readCancellation.CancelAfter(_options.ReadTimeout);
                try
                {
                    readResult = await reader.ReadAsync(readCancellation.Token).ConfigureAwait(false);
                    readCancellation.CancelAfter(Timeout.InfiniteTimeSpan);
                }
                catch (OperationCanceledException) when (!serverCancellationToken.IsCancellationRequested)
                {
                    return;
                }

                ReadOnlySequence<byte> buffer = readResult.Buffer;
                bool needMoreData = false;
                while (!buffer.IsEmpty)
                {
                    SipFrameStatus frameStatus = SipMessageFramer.TryRead(
                        buffer,
                        _options.Limits,
                        out ReadOnlySequence<byte> framedMessage);

                    if (frameStatus == SipFrameStatus.NeedMoreData)
                    {
                        needMoreData = true;
                        break;
                    }

                    if (frameStatus != SipFrameStatus.Complete)
                    {
                        response.WriteError(frameStatus == SipFrameStatus.TooLarge ? 513 : 400);
                        _ = await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                        reader.AdvanceTo(buffer.End);
                        return;
                    }

                    bool connectionLimitReached =
                        ++messageCount > _options.Limits.MaxMessagesPerConnection;

                    bool keepConnection = await DispatchAsync(
                        framedMessage,
                        context,
                        response,
                        handlerCancellation,
                        connectionLimitReached,
                        serverCancellationToken).ConfigureAwait(false);
                    buffer = buffer.Slice(framedMessage.End);
                    if (!keepConnection)
                    {
                        reader.AdvanceTo(buffer.Start);
                        return;
                    }
                }

                reader.AdvanceTo(buffer.Start, needMoreData ? buffer.End : buffer.Start);
                if (readResult.IsCompleted)
                {
                    if (!buffer.IsEmpty)
                    {
                        response.WriteError(400);
                        _ = await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                    }

                    return;
                }
            }
        }

        /// <summary>
        /// Parses and dispatches a framed message to the request handler.
        /// </summary>
        /// <param name="framedMessage">The complete framed message sequence.</param>
        /// <param name="context">The request context.</param>
        /// <param name="response">The response writer.</param>
        /// <param name="handlerCancellation">Cancellation source for handler timeout.</param>
        /// <param name="connectionLimitReached">
        /// Whether this message exceeded the per-connection message-count limit.
        /// </param>
        /// <param name="serverCancellationToken">Server shutdown token.</param>
        /// <returns>
        /// <see langword="true"/> if the connection may read another message; otherwise,
        /// <see langword="false"/>.
        /// </returns>
        private async ValueTask<bool> DispatchAsync(
            ReadOnlySequence<byte> framedMessage,
            SipRequestContext context,
            SipResponseWriter response,
            CancellationTokenSource handlerCancellation,
            bool connectionLimitReached,
            CancellationToken serverCancellationToken)
        {
            byte[]? rented = null;
            ReadOnlyMemory<byte> messageMemory;
            // Borrow single-segment memory; flatten segmented frames into a temporary pooled array.
            if (framedMessage.IsSingleSegment)
            {
                messageMemory = framedMessage.First;
            }
            else
            {
                rented = ArrayPool<byte>.Shared.Rent(checked((int)framedMessage.Length));
                framedMessage.CopyTo(rented);
                messageMemory = rented.AsMemory(0, (int)framedMessage.Length);
            }

            try
            {
                if (!TryParseForDispatch(messageMemory, out SipMessageMetadata metadata))
                {
                    if (!SipParser.TryCreateErrorView(messageMemory.Span, out SipMessageView errorView) ||
                        !response.WriteResponseAndClose(400, "Bad Request"u8, errorView))
                    {
                        response.WriteError(400);
                    }

                    _ = await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                    return false;
                }

                context.SetMessage(messageMemory, metadata);
                if (connectionLimitReached)
                {
                    if (!response.WriteResponseAndClose(503, "Service Unavailable"u8, context.Message))
                    {
                        response.WriteError(400);
                    }

                    _ = await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                    return false;
                }

                handlerCancellation.CancelAfter(_options.HandlerTimeout);
                try
                {
                    await _handler.HandleAsync(context, handlerCancellation.Token).ConfigureAwait(false);
                    handlerCancellation.CancelAfter(Timeout.InfiniteTimeSpan);
                }
                catch (OperationCanceledException) when (!serverCancellationToken.IsCancellationRequested)
                {
                    if (!response.HasPendingBytes &&
                        !response.WriteResponseAndClose(
                            500,
                            "Server Internal Error"u8,
                            context.Message))
                    {
                        response.WriteError(500);
                    }

                    if (response.HasPendingBytes)
                    {
                        response.ForceCloseAfterFlush();
                    }

                    _ = await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                    return false;
                }

                if (response.HasPendingBytes)
                {
                    bool closeAfterFlush = response.CloseAfterFlush;
                    FlushResult result = await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                    response.ResetAfterFlush();
                    return !closeAfterFlush && !result.IsCanceled && !result.IsCompleted;
                }

                return true;
            }
            finally
            {
                context.ClearMessage();
                if (rented is not null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }

        /// <summary>
        /// Parses a contiguous frame and retains only offsets needed to recreate its borrowed view.
        /// </summary>
        private bool TryParseForDispatch(ReadOnlyMemory<byte> memory, out SipMessageMetadata metadata)
        {
            if (!SipParser.TryParse(memory.Span, _options.Limits, out SipMessageView view, out _))
            {
                metadata = default;
                return false;
            }

            metadata = view.Metadata;
            return true;
        }

        /// <summary>
        /// Captures state for the allocation-conscious task continuation.
        /// </summary>
        private sealed record ConnectionCleanup(
            long Id,
            ConcurrentDictionary<long, Task> Connections,
            SemaphoreSlim Slots);
    }

}

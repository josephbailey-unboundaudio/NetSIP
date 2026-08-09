using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace NetSIP;

/// <summary>A bounded, cancellation-aware SIP over TLS server.</summary>
public sealed class SipTlsServer : IAsyncDisposable
{
    /// <summary>
    /// Server configuration options.
    /// </summary>
    private readonly SipTlsServerOptions _options;

    /// <summary>
    /// The request handler for processing SIP messages.
    /// </summary>
    private readonly ISipRequestHandler _handler;

    /// <summary>
    /// Logger for server operations.
    /// </summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Cancellation token source for the server lifetime.
    /// </summary>
    private readonly CancellationTokenSource _lifetime = new();

    /// <summary>
    /// Semaphore limiting concurrent connections.
    /// </summary>
    private readonly SemaphoreSlim _connectionSlots;

    /// <summary>
    /// Tracks active connection tasks by connection ID.
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
    /// Counter for assigning unique connection IDs.
    /// </summary>
    private long _nextConnectionId;

    /// <summary>
    /// Server state: 0 = not started, 1 = started, 2 = stopping/stopped.
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
    /// Gets the local endpoint the server is bound to after starting.
    /// Returns null if the server has not been started.
    /// </summary>
    public IPEndPoint? BoundEndPoint { get; private set; }

    /// <summary>
    /// Starts the server and begins accepting connections.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the start operation.</param>
    /// <returns>A completed task if startup succeeds.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the server has already been started.</exception>
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
        {
            throw new InvalidOperationException("The server has already been started.");
        }

        // Create and configure the listening socket
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
            // Clean up on failure
            listener.Dispose();
            _ = Interlocked.Exchange(ref _state, 0);
            throw;
        }
    }

    /// <summary>
    /// Stops the server gracefully, waiting for active connections to complete.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the stop operation.</param>
    /// <returns>A task that completes when the server has fully stopped.</returns>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        int priorState = Interlocked.Exchange(ref _state, 2);
        if (priorState == 0)
        {
            // Already stopped
            return;
        }

        if (priorState == 2)
        {
            // Stop already in progress
            SipLog.StopAlreadyInProgress(_logger);
        }
        else
        {
            // Cancel lifetime and close listener
            _lifetime.Cancel();
            _listener?.Dispose();
        }

        // Wait for accept loop to complete
        if (_acceptLoop is not null)
        {
            await _acceptLoop.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        // Wait for all active connections to complete
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
    /// Main accept loop that listens for and accepts incoming connections.
    /// </summary>
    private async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Wait for an available connection slot
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

                // Start handling the connection
                long connectionId = Interlocked.Increment(ref _nextConnectionId);
                Task connection = HandleConnectionAsync(connectionId, socket, cancellationToken);
                _ = _connections.TryAdd(connectionId, connection);

                // Schedule cleanup when connection completes
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
    /// Handles a single TLS connection through its full lifecycle:
    /// TLS handshake, message reading/dispatching, and cleanup.
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
    /// Processes incoming SIP messages from an authenticated connection.
    /// Frames, parses, and dispatches each message to the handler.
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
    /// <param name="connectionLimitReached">True if connection limit is reached.</param>
    /// <param name="serverCancellationToken">Server shutdown token.</param>
    /// <returns>True if the connection should remain open; false if it should close.</returns>
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
        // Flatten multi-segment messages into a contiguous buffer
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
    /// Parses a message and extracts metadata for dispatch.
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
    /// Captures cleanup state for a connection when it completes.
    /// </summary>
    private sealed record ConnectionCleanup(
        long Id,
        ConcurrentDictionary<long, Task> Connections,
        SemaphoreSlim Slots);
}

internal static partial class SipLog
{
    [LoggerMessage(1, LogLevel.Information, "SIP TLS server listening on {EndPoint}")]
    public static partial void ServerStarted(ILogger logger, EndPoint endPoint);

    [LoggerMessage(2, LogLevel.Information, "SIP TLS server stopped")]
    public static partial void ServerStopped(ILogger logger);

    [LoggerMessage(3, LogLevel.Debug, "Accepted connection {ConnectionId} from {RemoteEndPoint}")]
    public static partial void ConnectionAccepted(ILogger logger, long connectionId, EndPoint? remoteEndPoint);

    [LoggerMessage(4, LogLevel.Debug, "Connection {ConnectionId} from {RemoteEndPoint} closed")]
    public static partial void ConnectionClosed(ILogger logger, long connectionId, EndPoint? remoteEndPoint);

    [LoggerMessage(5, LogLevel.Debug, "TLS handshake failed for connection {ConnectionId} from {RemoteEndPoint}")]
    public static partial void TlsHandshakeFailed(
        ILogger logger,
        long connectionId,
        EndPoint? remoteEndPoint,
        Exception exception);

    [LoggerMessage(6, LogLevel.Debug, "I/O failed for connection {ConnectionId} from {RemoteEndPoint}")]
    public static partial void ConnectionIoFailed(
        ILogger logger,
        long connectionId,
        EndPoint? remoteEndPoint,
        Exception exception);

    [LoggerMessage(7, LogLevel.Debug, "Socket failed for connection {ConnectionId} from {RemoteEndPoint}")]
    public static partial void ConnectionSocketFailed(
        ILogger logger,
        long connectionId,
        EndPoint? remoteEndPoint,
        Exception exception);

    [LoggerMessage(8, LogLevel.Error, "Unhandled failure for connection {ConnectionId} from {RemoteEndPoint}")]
    public static partial void ConnectionFailed(
        ILogger logger,
        long connectionId,
        EndPoint? remoteEndPoint,
        Exception exception);

    [LoggerMessage(9, LogLevel.Debug, "Accept loop stopped with socket error {SocketError}")]
    public static partial void AcceptStopped(ILogger logger, SocketError socketError);

    [LoggerMessage(10, LogLevel.Debug, "SIP TLS server stop is already in progress")]
    public static partial void StopAlreadyInProgress(ILogger logger);

    [LoggerMessage(11, LogLevel.Warning, "Accept failed with socket error {SocketError}; retrying")]
    public static partial void AcceptFailed(ILogger logger, SocketError socketError);
}

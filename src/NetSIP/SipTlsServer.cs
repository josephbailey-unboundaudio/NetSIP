using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace NetSIP;

/// <summary>A bounded, cancellation-aware SIP over TLS server.</summary>
public sealed class SipTlsServer : IAsyncDisposable
{
    private readonly SipTlsServerOptions _options;
    private readonly ISipRequestHandler _handler;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _connectionSlots;
    private readonly ConcurrentDictionary<long, Task> _connections = new();
    private Socket? _listener;
    private Task? _acceptLoop;
    private long _nextConnectionId;
    private int _state;

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

    public IPEndPoint? BoundEndPoint { get; private set; }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
        {
            throw new InvalidOperationException("The server has already been started.");
        }

        var listener = new Socket(
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
            listener.Dispose();
            Interlocked.Exchange(ref _state, 0);
            throw;
        }
    }

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

        Task[] activeConnections = _connections.Values.ToArray();
        if (activeConnections.Length != 0)
        {
            await Task.WhenAll(activeConnections).WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        if (priorState == 1)
        {
            SipLog.ServerStopped(_logger);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _listener?.Dispose();
        _connectionSlots.Dispose();
        _lifetime.Dispose();
    }

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
                    _connectionSlots.Release();
                    throw;
                }

                long connectionId = Interlocked.Increment(ref _nextConnectionId);
                Task connection = HandleConnectionAsync(connectionId, socket, cancellationToken);
                _connections.TryAdd(connectionId, connection);
                _ = connection.ContinueWith(
                    static (_, state) =>
                    {
                        var cleanup = (ConnectionCleanup)state!;
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
            using (var networkStream = new NetworkStream(socket, ownsSocket: false))
            using (var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false))
            {
                using (var handshakeCancellation = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken))
                {
                    handshakeCancellation.CancelAfter(_options.HandshakeTimeout);
                    var authenticationOptions = new SslServerAuthenticationOptions
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

    private async Task ProcessMessagesAsync(
        EndPoint? remoteEndPoint,
        PipeReader reader,
        PipeWriter pipeWriter,
        CancellationToken serverCancellationToken)
    {
        var response = new SipResponseWriter(pipeWriter);
        var context = new SipRequestContext(remoteEndPoint, response);
        using var readCancellation = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken);
        using var handlerCancellation = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken);
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
                    await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
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
                    await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                }

                return;
            }
        }
    }

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

                await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
                return false;
            }

            context.SetMessage(messageMemory, metadata);
            if (connectionLimitReached)
            {
                if (!response.WriteResponseAndClose(503, "Service Unavailable"u8, context.Message))
                {
                    response.WriteError(400);
                }

                await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
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

                await response.FlushAsync(serverCancellationToken).ConfigureAwait(false);
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

using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Sockets;

namespace NetSIP;

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

using Microsoft.Extensions.Logging;
using System.Net;


namespace NetSIP;

internal static partial class SipAudioPlaybackLog
{
    [LoggerMessage(
        20,
        LogLevel.Warning,
        "Unable to create RTP playback session for {RemoteMedia}")]
    public static partial void SessionSetupFailed(
        ILogger logger,
        EndPoint remoteMedia,
        Exception exception);

    [LoggerMessage(
        21,
        LogLevel.Debug,
        "RTP playback session {SessionId} to {RemoteMedia} sent {SampleCount} samples")]
    public static partial void SessionCompleted(
        ILogger logger,
        long sessionId,
        EndPoint remoteMedia,
        int sampleCount);

    [LoggerMessage(
        22,
        LogLevel.Debug,
        "RTP playback session {SessionId} to {RemoteMedia} was canceled")]
    public static partial void SessionCanceled(
        ILogger logger,
        long sessionId,
        EndPoint remoteMedia);

    [LoggerMessage(
        23,
        LogLevel.Warning,
        "RTP playback session {SessionId} to {RemoteMedia} failed")]
    public static partial void SessionTransportFailed(
        ILogger logger,
        long sessionId,
        EndPoint remoteMedia,
        Exception exception);
}

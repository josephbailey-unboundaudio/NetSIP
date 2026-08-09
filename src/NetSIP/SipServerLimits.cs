namespace NetSIP;

/// <summary>
/// Defines protocol and connection limits enforced by the server.
/// </summary>
public sealed class SipServerLimits
{
    /// <summary>
    /// Gets or initializes the maximum size in bytes of the start line (request line or status line).
    /// The default is 2 KiB.
    /// </summary>
    public int MaxStartLineBytes { get; init; } = 2 * 1024;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of a single header line.
    /// The default is 8 KiB.
    /// </summary>
    public int MaxHeaderLineBytes { get; init; } = 8 * 1024;

    /// <summary>
    /// Gets or initializes the maximum combined size of the start line, header fields,
    /// and terminating CRLF sequence. The default is 64 KiB.
    /// </summary>
    public int MaxHeaderBytes { get; init; } = 64 * 1024;

    /// <summary>
    /// Gets or initializes the maximum number of header lines allowed in a message.
    /// The default is 128.
    /// </summary>
    public int MaxHeaderCount { get; init; } = 128;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of the message body.
    /// The default is 1 MiB. Zero permits only bodyless messages.
    /// </summary>
    public int MaxBodyBytes { get; init; } = 1024 * 1024;

    /// <summary>
    /// Gets or initializes the maximum number of SIP messages allowed on a single connection.
    /// The default is 10,000.
    /// </summary>
    public int MaxMessagesPerConnection { get; init; } = 10_000;

    /// <summary>
    /// Validates that all limit values are within acceptable ranges and consistent.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if any limit is out of range.</exception>
    /// <exception cref="ArgumentException">Thrown if limits are inconsistent.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxStartLineBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxHeaderLineBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxHeaderBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxHeaderCount);
        ArgumentOutOfRangeException.ThrowIfNegative(MaxBodyBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxMessagesPerConnection);

        // A per-line limit cannot be satisfiable when it exceeds the aggregate limit.
        if (MaxStartLineBytes > MaxHeaderBytes || MaxHeaderLineBytes > MaxHeaderBytes)
        {
            throw new ArgumentException("Start-line and header-line limits cannot exceed MaxHeaderBytes.");
        }
    }
}

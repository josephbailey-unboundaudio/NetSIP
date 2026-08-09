namespace NetSIP;

/// <summary>Defines protocol and connection limits enforced by the server.</summary>
public sealed class SipServerLimits
{
    /// <summary>
    /// Gets or initializes the maximum size in bytes of the start line (request line or status line).
    /// Default is 2KB.
    /// </summary>
    public int MaxStartLineBytes { get; init; } = 2 * 1024;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of a single header line.
    /// Default is 8KB.
    /// </summary>
    public int MaxHeaderLineBytes { get; init; } = 8 * 1024;

    /// <summary>
    /// Gets or initializes the maximum total size in bytes of all headers including the start line.
    /// Default is 64KB.
    /// </summary>
    public int MaxHeaderBytes { get; init; } = 64 * 1024;

    /// <summary>
    /// Gets or initializes the maximum number of header lines allowed in a message.
    /// Default is 128.
    /// </summary>
    public int MaxHeaderCount { get; init; } = 128;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of the message body.
    /// Default is 1MB.
    /// </summary>
    public int MaxBodyBytes { get; init; } = 1024 * 1024;

    /// <summary>
    /// Gets or initializes the maximum number of SIP messages allowed on a single connection.
    /// Default is 10,000.
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

        // Ensure individual line limits don't exceed total header limit
        if (MaxStartLineBytes > MaxHeaderBytes || MaxHeaderLineBytes > MaxHeaderBytes)
        {
            throw new ArgumentException("Start-line and header-line limits cannot exceed MaxHeaderBytes.");
        }
    }
}

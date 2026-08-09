namespace NetSIP;

/// <summary>Defines protocol and connection limits enforced by the server.</summary>
public sealed class SipServerLimits
{
    public int MaxStartLineBytes { get; init; } = 2 * 1024;

    public int MaxHeaderLineBytes { get; init; } = 8 * 1024;

    public int MaxHeaderBytes { get; init; } = 64 * 1024;

    public int MaxHeaderCount { get; init; } = 128;

    public int MaxBodyBytes { get; init; } = 1024 * 1024;

    public int MaxMessagesPerConnection { get; init; } = 10_000;

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxStartLineBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxHeaderLineBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxHeaderBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxHeaderCount);
        ArgumentOutOfRangeException.ThrowIfNegative(MaxBodyBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxMessagesPerConnection);

        if (MaxStartLineBytes > MaxHeaderBytes || MaxHeaderLineBytes > MaxHeaderBytes)
        {
            throw new ArgumentException("Start-line and header-line limits cannot exceed MaxHeaderBytes.");
        }
    }
}

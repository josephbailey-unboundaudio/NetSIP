namespace NetSIP;

/// <summary>
/// Configuration options for the bounded in-memory REGISTER handler.
/// </summary>
public sealed class SipRegisterHandlerOptions
{
    /// <summary>
    /// Gets or initializes the default expiration time in seconds for registrations.
    /// </summary>
    public int DefaultExpirationSeconds { get; init; } = 180;

    /// <summary>
    /// Gets or initializes the minimum allowed expiration time in seconds.
    /// </summary>
    public int MinimumExpirationSeconds { get; init; } = 90;

    /// <summary>
    /// Gets or initializes the maximum allowed expiration time in seconds.
    /// </summary>
    public int MaximumExpirationSeconds { get; init; } = 300;

    /// <summary>
    /// Gets or initializes the maximum number of addresses of record that can be stored.
    /// </summary>
    public int MaxAddressesOfRecord { get; init; } = 10_000;

    /// <summary>
    /// Gets or initializes the maximum number of bindings per address of record.
    /// </summary>
    public int MaxBindingsPerAddress { get; init; } = 32;

    /// <summary>
    /// Gets or initializes the maximum number of unique Call-IDs tracked per address.
    /// </summary>
    public int MaxCallIdsPerAddress { get; init; } = 64;

    /// <summary>
    /// Gets or initializes the maximum size of one complete Contact field value.
    /// </summary>
    public int MaxContactBytes { get; init; } = 2048;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of an address of record.
    /// </summary>
    public int MaxAddressOfRecordBytes { get; init; } = 512;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of a Call-ID.
    /// </summary>
    public int MaxCallIdBytes { get; init; } = 256;

    /// <summary>
    /// Gets or initializes the maximum estimated memory attributed to registrar state.
    /// </summary>
    public long MaxStoredBytes { get; init; } = 16 * 1024 * 1024;

    /// <summary>
    /// Validates that all options have valid values and consistent expiration policy.
    /// </summary>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(DefaultExpirationSeconds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MinimumExpirationSeconds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumExpirationSeconds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxAddressesOfRecord);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxBindingsPerAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxCallIdsPerAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxContactBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxAddressOfRecordBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxCallIdBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxStoredBytes);

        if (MinimumExpirationSeconds > DefaultExpirationSeconds ||
            DefaultExpirationSeconds > MaximumExpirationSeconds)
        {
            throw new ArgumentException(
                "Expiration policy must satisfy minimum <= default <= maximum.");
        }
    }
}


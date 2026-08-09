namespace NetSIP;

/// <summary>
/// Configures SIP Digest authentication.
/// </summary>
public sealed class SipDigestAuthenticationOptions
{
    /// <summary>
    /// Gets the printable ASCII authentication realm advertised to clients.
    /// Quote and backslash are not permitted.
    /// </summary>
    public required string Realm { get; init; }

    /// <summary>Gets the nonce lifetime, from one second through 24 hours.</summary>
    public TimeSpan NonceLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets the maximum live nonce/user replay records. Authentication fails closed
    /// when this capacity is occupied until an entry expires.
    /// </summary>
    public int MaxTrackedAuthentications { get; init; } = 4096;

    /// <summary>Gets the maximum accepted Authorization field-value size in bytes.</summary>
    public int MaxAuthorizationHeaderBytes { get; init; } = 4096;

    /// <summary>Gets the maximum UTF-8 username size.</summary>
    public int MaxUserNameBytes { get; init; } = 256;

    /// <summary>
    /// Gets the advertised algorithms. SHA-256 is the secure default; MD5 is legacy-only.
    /// </summary>
    public SipDigestAlgorithmFlags Algorithms { get; init; } = SipDigestAlgorithmFlags.Sha256;

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Realm);
        if (!IsSafeRealm(Realm))
        {
            throw new ArgumentException(
                "The digest realm must contain printable ASCII characters other than quote and backslash.",
                nameof(Realm));
        }

        if (NonceLifetime < TimeSpan.FromSeconds(1) ||
            NonceLifetime > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(
                nameof(NonceLifetime),
                "NonceLifetime must be between one second and 24 hours.");
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxTrackedAuthentications);
        if (MaxAuthorizationHeaderBytes is < 256 or > 64 * 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxAuthorizationHeaderBytes),
                "MaxAuthorizationHeaderBytes must be between 256 and 65536.");
        }

        if (MaxUserNameBytes is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxUserNameBytes),
                "MaxUserNameBytes must be between 1 and 4096.");
        }

        if (Algorithms == SipDigestAlgorithmFlags.None ||
            (Algorithms & ~(SipDigestAlgorithmFlags.Sha256 | SipDigestAlgorithmFlags.Md5)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(Algorithms));
        }
    }

    private static bool IsSafeRealm(string realm)
    {
        foreach (char value in realm)
        {
            if (value is < ' ' or > '~' or '"' or '\\')
            {
                return false;
            }
        }

        return true;
    }
}

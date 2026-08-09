namespace NetSIP;

/// <summary>
/// Identifies supported SIP Digest hash algorithms.
/// </summary>
[Flags]
public enum SipDigestAlgorithmFlags
{
    /// <summary>No algorithm is enabled.</summary>
    None = 0,

    /// <summary>SHA-256 is enabled and preferred.</summary>
    Sha256 = 1,

    /// <summary>Legacy MD5 is enabled for clients that cannot use SHA-256.</summary>
    Md5 = 2
}

namespace NetSIP;

/// <summary>
/// A borrowed header view that preserves every value byte following the first colon.
/// </summary>
public readonly ref struct SipHeaderView
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SipHeaderView"/> struct.
    /// </summary>
    /// <param name="name">The header name.</param>
    /// <param name="rawValue">The raw header value (may include leading/trailing whitespace).</param>
    internal SipHeaderView(ReadOnlySpan<byte> name, ReadOnlySpan<byte> rawValue)
    {
        Name = name;
        RawValue = rawValue;
    }

    /// <summary>
    /// Gets the header name.
    /// </summary>
    public ReadOnlySpan<byte> Name { get; }

    /// <summary>
    /// Gets the raw header value, including optional leading or trailing whitespace.
    /// </summary>
    public ReadOnlySpan<byte> RawValue { get; }

    /// <summary>
    /// Gets the header value with optional leading and trailing whitespace removed.
    /// </summary>
    public ReadOnlySpan<byte> Value => AsciiUtilities.TrimOptionalWhitespace(RawValue);
}

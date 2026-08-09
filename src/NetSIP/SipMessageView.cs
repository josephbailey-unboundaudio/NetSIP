namespace NetSIP;

/// <summary>
/// A borrowed, stack-only view over one complete SIP message. The view and every span
/// obtained from it are valid only while the source buffer remains valid.
/// </summary>
public readonly ref struct SipMessageView
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SipMessageView"/> struct.
    /// </summary>
    /// <param name="message">The complete message bytes.</param>
    /// <param name="metadata">The parsed metadata specifying offsets into the message.</param>
    internal SipMessageView(ReadOnlySpan<byte> message, SipMessageMetadata metadata)
    {
        Raw = message;
        Metadata = metadata;
    }

    /// <summary>
    /// Gets the message kind.
    /// </summary>
    public SipMessageKind Kind => Metadata.Kind;

    /// <summary>
    /// Gets the internal metadata containing offsets and lengths.
    /// </summary>
    internal SipMessageMetadata Metadata { get; }

    /// <summary>
    /// Gets the raw bytes of the complete SIP message.
    /// </summary>
    public ReadOnlySpan<byte> Raw { get; }

    /// <summary>
    /// Gets the SIP method, such as REGISTER or INVITE, for request messages.
    /// Returns an empty span for response messages.
    /// </summary>
    public ReadOnlySpan<byte> Method =>
        Kind == SipMessageKind.Request
            ? Raw.Slice(Metadata.FirstTokenOffset, Metadata.FirstTokenLength)
            : [];

    /// <summary>
    /// Gets the Request-URI for request messages.
    /// Returns an empty span for response messages.
    /// </summary>
    public ReadOnlySpan<byte> RequestUri =>
        Kind == SipMessageKind.Request
            ? Raw.Slice(Metadata.SecondTokenOffset, Metadata.SecondTokenLength)
            : [];

    /// <summary>
    /// Gets the SIP version bytes from the start line.
    /// </summary>
    public ReadOnlySpan<byte> Version =>
        Kind == SipMessageKind.Request
            ? Raw.Slice(Metadata.ThirdTokenOffset, Metadata.ThirdTokenLength)
            : Raw.Slice(Metadata.FirstTokenOffset, Metadata.FirstTokenLength);

    /// <summary>
    /// Gets the numeric status code for a response, or zero for a request.
    /// </summary>
    public int StatusCode => Metadata.StatusCode;

    /// <summary>
    /// Gets the reason phrase for response messages.
    /// Returns an empty span for request messages.
    /// </summary>
    public ReadOnlySpan<byte> ReasonPhrase =>
        Kind == SipMessageKind.Response
            ? Raw.Slice(Metadata.ThirdTokenOffset, Metadata.ThirdTokenLength)
            : [];

    /// <summary>
    /// Gets the message body, or an empty span when Content-Length is zero or absent.
    /// </summary>
    public ReadOnlySpan<byte> Body => Raw.Slice(Metadata.BodyOffset, Metadata.BodyLength);

    /// <summary>
    /// Creates a zero-allocation enumerator over the message headers.
    /// </summary>
    /// <returns>A header enumerator.</returns>
    public SipHeaderEnumerator GetHeaders()
    {
        return new(Raw.Slice(Metadata.HeadersOffset, Metadata.HeadersLength));
    }

    /// <summary>
    /// Attempts to find the first header with the specified ASCII case-insensitive name.
    /// </summary>
    /// <param name="name">The header name to search for.</param>
    /// <param name="value">When this method returns, contains the header value if found.</param>
    /// <returns>true if a header with the specified name was found; otherwise, false.</returns>
    public bool TryGetHeader(ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value)
    {
        SipHeaderEnumerator headers = GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (AsciiUtilities.EqualsIgnoreCase(header.Name, name))
            {
                value = header.Value;
                return true;
            }
        }

        value = default;
        return false;
    }
}

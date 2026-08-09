namespace NetSIP;

/// <summary>
/// Identifies whether a parsed SIP start line represents a request or response.
/// </summary>
public enum SipMessageKind
{
    /// <summary>
    /// A SIP request message, such as REGISTER or INVITE.
    /// </summary>
    Request,

    /// <summary>
    /// A SIP response message, such as 200 OK or 404 Not Found.
    /// </summary>
    Response
}

/// <summary>
/// Identifies why a complete SIP message could not be parsed.
/// </summary>
public enum SipParseError
{
    /// <summary>
    /// No error occurred; parsing was successful.
    /// </summary>
    None,

    /// <summary>
    /// The message is incomplete and more data is needed.
    /// </summary>
    Incomplete,

    /// <summary>
    /// The start line (request line or status line) is malformed.
    /// </summary>
    MalformedStartLine,

    /// <summary>
    /// One or more headers are malformed.
    /// </summary>
    MalformedHeader,

    /// <summary>
    /// Content-Length is malformed, conflicting, or inconsistent with the frame size.
    /// </summary>
    InvalidContentLength,

    /// <summary>
    /// The message exceeds the maximum allowed size.
    /// </summary>
    MessageTooLarge
}

/// <summary>
/// Identifies the result of extracting one SIP frame from a transport buffer.
/// </summary>
public enum SipFrameStatus
{
    /// <summary>
    /// A complete message frame was successfully extracted.
    /// </summary>
    Complete,

    /// <summary>
    /// More data is needed to complete the message frame.
    /// </summary>
    NeedMoreData,

    /// <summary>
    /// The message frame is malformed and cannot be parsed.
    /// </summary>
    Malformed,

    /// <summary>
    /// The message frame exceeds the maximum allowed size.
    /// </summary>
    TooLarge
}

/// <summary>
/// Stores offsets into the source buffer so message views do not allocate owned values.
/// </summary>
internal readonly struct SipMessageMetadata(
    SipMessageKind kind,
    int firstTokenOffset,
    int firstTokenLength,
    int secondTokenOffset,
    int secondTokenLength,
    int thirdTokenOffset,
    int thirdTokenLength,
    int statusCode,
    int headersOffset,
    int headersLength,
    int bodyOffset,
    int bodyLength)
{
    /// <summary>
    /// Gets the message kind.
    /// </summary>
    public SipMessageKind Kind { get; } = kind;

    /// <summary>
    /// Gets the offset of the method for requests or version for responses.
    /// </summary>
    public int FirstTokenOffset { get; } = firstTokenOffset;

    /// <summary>
    /// Gets the length of the first token.
    /// </summary>
    public int FirstTokenLength { get; } = firstTokenLength;

    /// <summary>
    /// Gets the offset of the request URI for requests or status code for responses.
    /// </summary>
    public int SecondTokenOffset { get; } = secondTokenOffset;

    /// <summary>
    /// Gets the length of the second token.
    /// </summary>
    public int SecondTokenLength { get; } = secondTokenLength;

    /// <summary>
    /// Gets the offset of the version for requests or reason phrase for responses.
    /// </summary>
    public int ThirdTokenOffset { get; } = thirdTokenOffset;

    /// <summary>
    /// Gets the length of the third token.
    /// </summary>
    public int ThirdTokenLength { get; } = thirdTokenLength;

    /// <summary>
    /// Gets the numeric response status code, or zero for a request.
    /// </summary>
    public int StatusCode { get; } = statusCode;

    /// <summary>
    /// Gets the offset where headers begin.
    /// </summary>
    public int HeadersOffset { get; } = headersOffset;

    /// <summary>
    /// Gets the total length of the headers section.
    /// </summary>
    public int HeadersLength { get; } = headersLength;

    /// <summary>
    /// Gets the offset where the message body begins.
    /// </summary>
    public int BodyOffset { get; } = bodyOffset;

    /// <summary>
    /// Gets the length of the message body.
    /// </summary>
    public int BodyLength { get; } = bodyLength;
}

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
            if (Ascii.EqualsIgnoreCase(header.Name, name))
            {
                value = header.Value;
                return true;
            }
        }

        value = default;
        return false;
    }
}

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
    public ReadOnlySpan<byte> Value => Ascii.TrimOptionalWhitespace(RawValue);
}

/// <summary>
/// Enumerates borrowed headers without allocating. The source must remain valid
/// for the lifetime of the enumerator.
/// </summary>
public ref struct SipHeaderEnumerator
{
    /// <summary>
    /// The remaining unparsed header bytes.
    /// </summary>
    private ReadOnlySpan<byte> _remaining;

    /// <summary>
    /// Initializes a new instance of the <see cref="SipHeaderEnumerator"/> struct.
    /// </summary>
    /// <param name="headers">The complete headers section bytes to enumerate.</param>
    internal SipHeaderEnumerator(ReadOnlySpan<byte> headers)
    {
        _remaining = headers;
        Current = default;
    }

    /// <summary>
    /// Gets the current header in the enumeration.
    /// </summary>
    public SipHeaderView Current { get; private set; }

    /// <summary>
    /// Advances the enumerator to the next header.
    /// </summary>
    /// <returns>true if a valid header was found; false if no more headers remain.</returns>
    public bool MoveNext()
    {
        while (!_remaining.IsEmpty)
        {
            int lineEnd = _remaining.IndexOf("\r\n"u8);
            ReadOnlySpan<byte> line;
            if (lineEnd < 0)
            {
                line = _remaining;
                _remaining = [];
            }
            else
            {
                line = _remaining[..lineEnd];
                _remaining = _remaining[(lineEnd + 2)..];
            }

            int colon = line.IndexOf((byte)':');
            if (colon <= 0)
            {
                // Parsed messages cannot reach this path; tolerate it for minimal error views.
                continue;
            }

            Current = new SipHeaderView(line[..colon], line[(colon + 1)..]);
            return true;
        }

        return false;
    }
}

/// <summary>
/// Provides allocation-free ASCII operations used by SIP parsing and matching.
/// </summary>
internal static class Ascii
{
    /// <summary>
    /// Compares two byte spans for equality, ignoring ASCII case differences.
    /// </summary>
    /// <param name="left">The first span to compare.</param>
    /// <param name="right">The second span to compare.</param>
    /// <returns>true if the spans are equal (case-insensitive); otherwise, false.</returns>
    public static bool EqualsIgnoreCase(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        for (int i = 0; i < left.Length; i++)
        {
            byte a = left[i];
            byte b = right[i];
            if (a == b)
            {
                continue;
            }

            if ((uint)(a - (byte)'A') <= 'Z' - 'A')
            {
                a = (byte)(a + ('a' - 'A'));
            }

            if ((uint)(b - (byte)'A') <= 'Z' - 'A')
            {
                b = (byte)(b + ('a' - 'A'));
            }

            if (a != b)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Removes optional whitespace (space and tab) from the beginning and end of a byte span.
    /// </summary>
    /// <param name="value">The span to trim.</param>
    /// <returns>The trimmed span.</returns>
    public static ReadOnlySpan<byte> TrimOptionalWhitespace(ReadOnlySpan<byte> value)
    {
        int start = 0;
        while (start < value.Length && IsOptionalWhitespace(value[start]))
        {
            start++;
        }

        int end = value.Length;
        while (end > start && IsOptionalWhitespace(value[end - 1]))
        {
            end--;
        }

        return value[start..end];
    }

    /// <summary>
    /// Determines whether a byte represents optional whitespace (space or tab).
    /// </summary>
    /// <param name="value">The byte to check.</param>
    /// <returns>true if the byte is a space or tab; otherwise, false.</returns>
    public static bool IsOptionalWhitespace(byte value)
    {
        return value is (byte)' ' or (byte)'\t';
    }

    /// <summary>
    /// Determines whether a byte is a valid SIP token character according to RFC 3261.
    /// Token characters are printable ASCII excluding separators and special characters.
    /// </summary>
    /// <param name="value">The byte to check.</param>
    /// <returns>true if the byte is a valid token character; otherwise, false.</returns>
    public static bool IsTokenByte(byte value)
    {
        return value is >= 0x21 and <= 0x7e and
        not (byte)'(' and not (byte)')' and not (byte)'<' and not (byte)'>' and
        not (byte)'@' and not (byte)',' and not (byte)';' and not (byte)':' and
        not (byte)'\\' and not (byte)'"' and not (byte)'/' and not (byte)'[' and
        not (byte)']' and not (byte)'?' and not (byte)'=' and not (byte)'{' and not (byte)'}';
    }
}

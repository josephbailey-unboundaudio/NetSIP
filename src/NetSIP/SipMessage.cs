namespace NetSIP;

/// <summary>
/// Specifies the type of a SIP message.
/// </summary>
public enum SipMessageKind
{
    /// <summary>
    /// A SIP request message (e.g., REGISTER, INVITE).
    /// </summary>
    Request,

    /// <summary>
    /// A SIP response message (e.g., 200 OK, 404 Not Found).
    /// </summary>
    Response
}

/// <summary>
/// Defines the types of errors that can occur when parsing a SIP message.
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
    /// The Content-Length header contains an invalid value.
    /// </summary>
    InvalidContentLength,

    /// <summary>
    /// The message exceeds the maximum allowed size.
    /// </summary>
    MessageTooLarge
}

/// <summary>
/// Indicates the status of a SIP message frame extraction.
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
/// Internal metadata structure that stores offsets and lengths for different parts of a parsed SIP message.
/// This allows zero-allocation message parsing by storing only offsets into the original buffer.
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
    /// Gets the message kind (Request or Response).
    /// </summary>
    public SipMessageKind Kind { get; } = kind;

    /// <summary>
    /// Gets the offset of the first token in the start line (Method for requests, Version for responses).
    /// </summary>
    public int FirstTokenOffset { get; } = firstTokenOffset;

    /// <summary>
    /// Gets the length of the first token.
    /// </summary>
    public int FirstTokenLength { get; } = firstTokenLength;

    /// <summary>
    /// Gets the offset of the second token in the start line (Request-URI for requests, Status-Code for responses).
    /// </summary>
    public int SecondTokenOffset { get; } = secondTokenOffset;

    /// <summary>
    /// Gets the length of the second token.
    /// </summary>
    public int SecondTokenLength { get; } = secondTokenLength;

    /// <summary>
    /// Gets the offset of the third token in the start line (Version for requests, Reason-Phrase for responses).
    /// </summary>
    public int ThirdTokenOffset { get; } = thirdTokenOffset;

    /// <summary>
    /// Gets the length of the third token.
    /// </summary>
    public int ThirdTokenLength { get; } = thirdTokenLength;

    /// <summary>
    /// Gets the numeric status code for response messages.
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
    /// Gets the message kind (Request or Response).
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
    /// Gets the SIP method (e.g., "REGISTER", "INVITE") for request messages.
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
    /// Gets the SIP version string (e.g., "SIP/2.0") from the message.
    /// </summary>
    public ReadOnlySpan<byte> Version =>
        Kind == SipMessageKind.Request
            ? Raw.Slice(Metadata.ThirdTokenOffset, Metadata.ThirdTokenLength)
            : Raw.Slice(Metadata.FirstTokenOffset, Metadata.FirstTokenLength);

    /// <summary>
    /// Gets the numeric status code for response messages.
    /// </summary>
    public int StatusCode => Metadata.StatusCode;

    /// <summary>
    /// Gets the reason phrase for response messages (e.g., "OK", "Not Found").
    /// Returns an empty span for request messages.
    /// </summary>
    public ReadOnlySpan<byte> ReasonPhrase =>
        Kind == SipMessageKind.Response
            ? Raw.Slice(Metadata.ThirdTokenOffset, Metadata.ThirdTokenLength)
            : [];

    /// <summary>
    /// Gets the message body bytes.
    /// </summary>
    public ReadOnlySpan<byte> Body => Raw.Slice(Metadata.BodyOffset, Metadata.BodyLength);

    /// <summary>
    /// Creates an enumerator to iterate through all headers in the message.
    /// </summary>
    /// <returns>A header enumerator.</returns>
    public SipHeaderEnumerator GetHeaders()
    {
        return new(Raw.Slice(Metadata.HeadersOffset, Metadata.HeadersLength));
    }

    /// <summary>
    /// Attempts to find a header with the specified name (case-insensitive).
    /// </summary>
    /// <param name="name">The header name to search for.</param>
    /// <param name="value">When this method returns, contains the header value if found.</param>
    /// <returns>true if a header with the specified name was found; otherwise, false.</returns>
    public bool TryGetHeader(ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value)
    {
        // Iterate through all headers
        SipHeaderEnumerator headers = GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            // Case-insensitive comparison of header names
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

/// <summary>A borrowed view over a SIP header, preserving the exact bytes after the colon.</summary>
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
    /// Gets the raw header value, preserving all bytes after the colon.
    /// </summary>
    public ReadOnlySpan<byte> RawValue { get; }

    /// <summary>
    /// Gets the header value with optional leading and trailing whitespace removed.
    /// </summary>
    public ReadOnlySpan<byte> Value => Ascii.TrimOptionalWhitespace(RawValue);
}

/// <summary>Enumerates headers without allocating or building a header collection.</summary>
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
            // Find the end of the current line
            int lineEnd = _remaining.IndexOf("\r\n"u8);
            ReadOnlySpan<byte> line;
            if (lineEnd < 0)
            {
                // Last line without CRLF
                line = _remaining;
                _remaining = [];
            }
            else
            {
                line = _remaining[..lineEnd];
                _remaining = _remaining[(lineEnd + 2)..];
            }

            // Find the colon separating name and value
            int colon = line.IndexOf((byte)':');
            if (colon <= 0)
            {
                // Skip malformed headers
                continue;
            }

            // Split into name and value at the colon
            Current = new SipHeaderView(line[..colon], line[(colon + 1)..]);
            return true;
        }

        return false;
    }
}

/// <summary>
/// Provides ASCII-specific string operations for efficient SIP message parsing.
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

            // Convert uppercase ASCII to lowercase
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
        // Trim leading whitespace
        while (start < value.Length && IsOptionalWhitespace(value[start]))
        {
            start++;
        }

        int end = value.Length;
        // Trim trailing whitespace
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
        // Valid token bytes are printable ASCII (0x21-0x7E) excluding separators
        return value is >= 0x21 and <= 0x7e and
        not (byte)'(' and not (byte)')' and not (byte)'<' and not (byte)'>' and
        not (byte)'@' and not (byte)',' and not (byte)';' and not (byte)':' and
        not (byte)'\\' and not (byte)'"' and not (byte)'/' and not (byte)'[' and
        not (byte)']' and not (byte)'?' and not (byte)'=' and not (byte)'{' and not (byte)'}';
    }
}

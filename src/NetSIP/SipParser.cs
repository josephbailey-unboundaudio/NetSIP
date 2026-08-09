namespace NetSIP;

/// <summary>Parses complete SIP messages directly from bytes without allocating.</summary>
public static class SipParser
{
    /// <summary>
    /// Attempts to create a minimal message view from a potentially malformed request,
    /// useful for extracting enough information to generate an error response.
    /// </summary>
    /// <param name="message">The raw message bytes.</param>
    /// <param name="view">When this method returns true, contains a view over the parsed request.</param>
    /// <returns>true if a minimal request view could be created; otherwise, false.</returns>
    internal static bool TryCreateErrorView(ReadOnlySpan<byte> message, out SipMessageView view)
    {
        // Attempt to find the header/body separator
        int headerTerminator = message.IndexOf("\r\n\r\n"u8);
        int startLineEnd = headerTerminator < 0
            ? -1
            : message[..headerTerminator].IndexOf("\r\n"u8);
        if (startLineEnd <= 0 ||
            !TryParseStartLine(message[..startLineEnd], out StartLineParts startLine) ||
            startLine.Kind != SipMessageKind.Request)
        {
            view = default;
            return false;
        }

        int headersOffset = startLineEnd + 2;
        SipMessageMetadata metadata = new(
            startLine.Kind,
            startLine.FirstOffset,
            startLine.FirstLength,
            startLine.SecondOffset,
            startLine.SecondLength,
            startLine.ThirdOffset,
            startLine.ThirdLength,
            startLine.StatusCode,
            headersOffset,
            headerTerminator - headersOffset,
            headerTerminator + 4,
            0);
        view = new SipMessageView(message, metadata);
        return true;
    }

    /// <summary>
    /// Attempts to parse a complete SIP message from the provided bytes.
    /// </summary>
    /// <param name="message">The raw message bytes to parse.</param>
    /// <param name="limits">The server limits to enforce during parsing.</param>
    /// <param name="view">When this method returns true, contains a view over the parsed message.</param>
    /// <param name="error">When this method returns false, contains the parse error that occurred.</param>
    /// <returns>true if the message was successfully parsed; otherwise, false.</returns>
    public static bool TryParse(
        ReadOnlySpan<byte> message,
        SipServerLimits limits,
        out SipMessageView view,
        out SipParseError error)
    {
        ArgumentNullException.ThrowIfNull(limits);

        // Find the header/body separator (double CRLF)
        int headerTerminator = message.IndexOf("\r\n\r\n"u8);
        if (headerTerminator < 0)
        {
            view = default;
            error = message.Length > limits.MaxHeaderBytes
                ? SipParseError.MessageTooLarge
                : SipParseError.Incomplete;
            return false;
        }

        // Check total header size
        int headerBytes = headerTerminator + 4;
        if (headerBytes > limits.MaxHeaderBytes)
        {
            view = default;
            error = SipParseError.MessageTooLarge;
            return false;
        }

        // Find and validate the start line
        int startLineEnd = message[..headerTerminator].IndexOf("\r\n"u8);
        if (startLineEnd <= 0)
        {
            view = default;
            error = SipParseError.MalformedStartLine;
            return false;
        }

        if (startLineEnd > limits.MaxStartLineBytes)
        {
            view = default;
            error = SipParseError.MessageTooLarge;
            return false;
        }

        if (!TryParseStartLine(message[..startLineEnd], out StartLineParts startLine))
        {
            view = default;
            error = SipParseError.MalformedStartLine;
            return false;
        }

        // Parse and validate all headers
        int headersOffset = startLineEnd + 2;
        int cursor = headersOffset;
        int headerCount = 0;
        int contentLength = 0;
        bool contentLengthSeen = false;

        while (cursor < headerTerminator)
        {
            int relativeLineEnd = message[cursor..headerTerminator].IndexOf("\r\n"u8);
            int lineEnd = relativeLineEnd < 0 ? headerTerminator : cursor + relativeLineEnd;
            ReadOnlySpan<byte> line = message[cursor..lineEnd];

            // Validate header line length and count
            if (line.IsEmpty || line.Length > limits.MaxHeaderLineBytes || ++headerCount > limits.MaxHeaderCount)
            {
                view = default;
                error = line.Length > limits.MaxHeaderLineBytes || headerCount > limits.MaxHeaderCount
                    ? SipParseError.MessageTooLarge
                    : SipParseError.MalformedHeader;
                return false;
            }

            // Check for header folding (not allowed in SIP/2.0)
            if (Ascii.IsOptionalWhitespace(line[0]))
            {
                view = default;
                error = SipParseError.MalformedHeader;
                return false;
            }

            // Find colon and validate header structure
            int colon = line.IndexOf((byte)':');
            if (colon <= 0 ||
                !IsValidHeaderName(line[..colon]) ||
                !IsValidHeaderValue(line[(colon + 1)..]))
            {
                view = default;
                error = SipParseError.MalformedHeader;
                return false;
            }

            // Special handling for Content-Length header (or compact form 'l')
            ReadOnlySpan<byte> name = line[..colon];
            if (Ascii.EqualsIgnoreCase(name, "Content-Length"u8) || Ascii.EqualsIgnoreCase(name, "l"u8))
            {
                if (!TryParseContentLength(line[(colon + 1)..], out int parsedLength) ||
                    (contentLengthSeen && parsedLength != contentLength))
                {
                    view = default;
                    error = SipParseError.InvalidContentLength;
                    return false;
                }

                contentLength = parsedLength;
                contentLengthSeen = true;
            }

            cursor = lineEnd + 2;
        }

        // Validate content length
        if (contentLength > limits.MaxBodyBytes)
        {
            view = default;
            error = SipParseError.MessageTooLarge;
            return false;
        }

        // Check if we have complete body
        if (message.Length < headerBytes + contentLength)
        {
            view = default;
            error = SipParseError.Incomplete;
            return false;
        }

        // Validate exact message length matches Content-Length
        if (message.Length != headerBytes + contentLength)
        {
            view = default;
            error = SipParseError.InvalidContentLength;
            return false;
        }

        // Create metadata and view
        SipMessageMetadata metadata = new(
            startLine.Kind,
            startLine.FirstOffset,
            startLine.FirstLength,
            startLine.SecondOffset,
            startLine.SecondLength,
            startLine.ThirdOffset,
            startLine.ThirdLength,
            startLine.StatusCode,
            headersOffset,
            headerTerminator - headersOffset,
            headerBytes,
            contentLength);

        view = new SipMessageView(message, metadata);
        error = SipParseError.None;
        return true;
    }

    /// <summary>
    /// Parses the start line of a SIP message (either a request line or status line).
    /// </summary>
    /// <param name="line">The start line bytes.</param>
    /// <param name="result">When this method returns true, contains the parsed start line parts.</param>
    /// <returns>true if the start line was successfully parsed; otherwise, false.</returns>
    private static bool TryParseStartLine(ReadOnlySpan<byte> line, out StartLineParts result)
    {
        // Check for control characters (excluding space and tab)
        foreach (byte value in line)
        {
            if (value is (< 0x20 and not (byte)' ' and not (byte)'\t') or 0x7f)
            {
                result = default;
                return false;
            }
        }

        int firstSpace = line.IndexOf((byte)' ');
        if (firstSpace <= 0)
        {
            result = default;
            return false;
        }

        // Check if this is a response (starts with "SIP/2.0 ")
        if (line.StartsWith("SIP/2.0 "u8))
        {
            // Parse response status line: SIP/2.0 <status-code> <reason-phrase>
            ReadOnlySpan<byte> remainder = line[(firstSpace + 1)..];
            int secondSpace = remainder.IndexOf((byte)' ');
            ReadOnlySpan<byte> status = secondSpace < 0 ? remainder : remainder[..secondSpace];

            // Validate 3-digit status code (1xx-6xx)
            if (status.Length != 3 ||
                status[0] is < (byte)'1' or > (byte)'6' ||
                status[1] is < (byte)'0' or > (byte)'9' ||
                status[2] is < (byte)'0' or > (byte)'9')
            {
                result = default;
                return false;
            }

            // Parse status code to integer
            int statusCode = ((status[0] - '0') * 100) + ((status[1] - '0') * 10) + status[2] - '0';
            int reasonOffset = secondSpace < 0 ? line.Length : firstSpace + 1 + secondSpace + 1;
            result = new StartLineParts(
                SipMessageKind.Response,
                0,
                firstSpace,
                firstSpace + 1,
                status.Length,
                reasonOffset,
                line.Length - reasonOffset,
                statusCode);
            return true;
        }

        // Parse request line: <method> <request-uri> SIP/2.0
        ReadOnlySpan<byte> method = line[..firstSpace];
        if (!IsValidHeaderName(method))
        {
            result = default;
            return false;
        }

        ReadOnlySpan<byte> requestRemainder = line[(firstSpace + 1)..];
        int secondRequestSpace = requestRemainder.IndexOf((byte)' ');
        if (secondRequestSpace <= 0)
        {
            result = default;
            return false;
        }

        int versionOffset = firstSpace + 1 + secondRequestSpace + 1;
        ReadOnlySpan<byte> requestUri = requestRemainder[..secondRequestSpace];

        // Validate Request-URI characters
        foreach (byte value in requestUri)
        {
            if (value is <= 0x20 or 0x7f)
            {
                result = default;
                return false;
            }
        }

        // Validate SIP version is exactly "SIP/2.0"
        if (!line[versionOffset..].SequenceEqual("SIP/2.0"u8))
        {
            result = default;
            return false;
        }

        result = new StartLineParts(
            SipMessageKind.Request,
            0,
            firstSpace,
            firstSpace + 1,
            secondRequestSpace,
            versionOffset,
            7,
            0);
        return true;
    }

    /// <summary>
    /// Validates that a header name contains only valid token characters.
    /// </summary>
    /// <param name="name">The header name to validate.</param>
    /// <returns>true if the name is valid; otherwise, false.</returns>
    private static bool IsValidHeaderName(ReadOnlySpan<byte> name)
    {
        if (name.IsEmpty)
        {
            return false;
        }

        foreach (byte value in name)
        {
            if (!Ascii.IsTokenByte(value))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Validates that a header value contains only valid characters (printable ASCII and tab).
    /// </summary>
    /// <param name="value">The header value to validate.</param>
    /// <returns>true if the value is valid; otherwise, false.</returns>
    private static bool IsValidHeaderValue(ReadOnlySpan<byte> value)
    {
        foreach (byte current in value)
        {
            // Allow tab and printable characters (0x20-0x7E), but not control characters or DEL
            if (current is (< 0x20 and not ((byte)'\t')) or 0x7f)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Attempts to parse a Content-Length header value to an integer.
    /// </summary>
    /// <param name="value">The header value bytes.</param>
    /// <param name="result">When this method returns true, contains the parsed length.</param>
    /// <returns>true if the value was successfully parsed; otherwise, false.</returns>
    private static bool TryParseContentLength(ReadOnlySpan<byte> value, out int result)
    {
        value = Ascii.TrimOptionalWhitespace(value);
        if (value.IsEmpty)
        {
            result = 0;
            return false;
        }

        int parsed = 0;
        foreach (byte digit in value)
        {
            // Validate digit and check for overflow
            if (digit is < (byte)'0' or > (byte)'9' ||
                parsed > (int.MaxValue - (digit - '0')) / 10)
            {
                result = 0;
                return false;
            }

            parsed = (parsed * 10) + digit - '0';
        }

        result = parsed;
        return true;
    }

    /// <summary>
    /// Internal structure holding the parsed components of a SIP start line.
    /// Stores offsets and lengths rather than allocating strings.
    /// </summary>
    private readonly record struct StartLineParts(
        SipMessageKind Kind,
        int FirstOffset,
        int FirstLength,
        int SecondOffset,
        int SecondLength,
        int ThirdOffset,
        int ThirdLength,
        int StatusCode);
}

using System.Buffers;

namespace NetSIP;

/// <summary>Finds complete SIP messages in a possibly segmented transport buffer.</summary>
public static class SipMessageFramer
{
    /// <summary>
    /// Gets the header terminator sequence (CRLF CRLF).
    /// </summary>
    private static ReadOnlySpan<byte> HeaderTerminator => "\r\n\r\n"u8;

    /// <summary>
    /// Gets the CRLF line terminator sequence.
    /// </summary>
    private static ReadOnlySpan<byte> CrLf => "\r\n"u8;

    /// <summary>
    /// Attempts to extract a complete SIP message frame from a possibly segmented buffer.
    /// </summary>
    /// <param name="input">The input buffer that may contain one or more SIP messages.</param>
    /// <param name="limits">The server limits to enforce during framing.</param>
    /// <param name="message">When this method returns Complete, contains the complete message frame.</param>
    /// <returns>The framing status indicating completion, truncation, malformed framing, or excess size.</returns>
    public static SipFrameStatus TryRead(
        in ReadOnlySequence<byte> input,
        SipServerLimits limits,
        out ReadOnlySequence<byte> message)
    {
        ArgumentNullException.ThrowIfNull(limits);
        message = default;

        SequenceReader<byte> reader = new(input);
        if (!reader.TryReadTo(out ReadOnlySequence<byte> headerBlock, HeaderTerminator, advancePastDelimiter: true))
        {
            return input.Length > limits.MaxHeaderBytes
                ? SipFrameStatus.TooLarge
                : SipFrameStatus.NeedMoreData;
        }

        long headerBytes = headerBlock.Length + HeaderTerminator.Length;
        if (headerBytes > limits.MaxHeaderBytes)
        {
            return SipFrameStatus.TooLarge;
        }

        // Inspect lines only as far as framing requires; SipParser performs full validation.
        SequenceReader<byte> lineReader = new(headerBlock);
        int lineNumber = 0;
        int headerCount = 0;
        int contentLength = 0;
        bool contentLengthSeen = false;

        while (!lineReader.End)
        {
            if (!lineReader.TryReadTo(out ReadOnlySequence<byte> line, CrLf, advancePastDelimiter: true))
            {
                line = headerBlock.Slice(lineReader.Position);
                lineReader.Advance(line.Length);
            }

            if (lineNumber++ == 0)
            {
                if (line.IsEmpty)
                {
                    return SipFrameStatus.Malformed;
                }

                if (line.Length > limits.MaxStartLineBytes)
                {
                    return SipFrameStatus.TooLarge;
                }

                continue;
            }

            if (line.IsEmpty)
            {
                return SipFrameStatus.Malformed;
            }

            if (line.Length > limits.MaxHeaderLineBytes || ++headerCount > limits.MaxHeaderCount)
            {
                return SipFrameStatus.TooLarge;
            }

            if (!TryInspectHeader(
                    line,
                    ref contentLengthSeen,
                    ref contentLength,
                    out bool invalidContentLength))
            {
                return invalidContentLength ? SipFrameStatus.Malformed : SipFrameStatus.Malformed;
            }
        }

        if (contentLength > limits.MaxBodyBytes)
        {
            return SipFrameStatus.TooLarge;
        }

        long totalLength = headerBytes + contentLength;
        if (input.Length < totalLength)
        {
            return SipFrameStatus.NeedMoreData;
        }

        message = input.Slice(0, totalLength);
        return SipFrameStatus.Complete;
    }

    /// <summary>
    /// Inspects enough of a header line to locate and validate Content-Length.
    /// Other field validation is deliberately deferred to <see cref="SipParser"/>.
    /// </summary>
    /// <param name="line">The header line to inspect.</param>
    /// <param name="contentLengthSeen">Tracks whether Content-Length has been seen before.</param>
    /// <param name="contentLength">The accumulated Content-Length value.</param>
    /// <param name="invalidContentLength">Set to true if the Content-Length is invalid.</param>
    /// <returns><see langword="false"/> only when Content-Length framing is invalid.</returns>
    private static bool TryInspectHeader(
        in ReadOnlySequence<byte> line,
        ref bool contentLengthSeen,
        ref int contentLength,
        out bool invalidContentLength)
    {
        invalidContentLength = false;
        SequenceReader<byte> reader = new(line);

        // A continuation line cannot introduce a new Content-Length field.
        if (!reader.TryPeek(out byte first) || Ascii.IsOptionalWhitespace(first))
        {
            return true;
        }

        // Malformed non-critical names are rejected later by the complete parser.
        if (!reader.TryReadTo(out ReadOnlySequence<byte> name, (byte)':', advancePastDelimiter: true) ||
            name.IsEmpty ||
            !IsValidHeaderName(name))
        {
            return true;
        }

        ReadOnlySequence<byte> value = line.Slice(reader.Position);
        if (!IsValidHeaderValue(value))
        {
            // Invalid non-critical values cannot affect the frame boundary.
            return !SequenceEqualsIgnoreCase(name, "Content-Length"u8) &&
                !SequenceEqualsIgnoreCase(name, "l"u8);
        }

        if (!SequenceEqualsIgnoreCase(name, "Content-Length"u8) &&
            !SequenceEqualsIgnoreCase(name, "l"u8))
        {
            return true;
        }

        if (!TryParseContentLength(value, out int parsedLength) ||
            (contentLengthSeen && parsedLength != contentLength))
        {
            invalidContentLength = true;
            return false;
        }

        contentLengthSeen = true;
        contentLength = parsedLength;
        return true;
    }

    /// <summary>
    /// Validates that a header name (in a ReadOnlySequence) contains only valid token characters.
    /// </summary>
    /// <param name="name">The header name sequence to validate.</param>
    /// <returns>true if the name is valid; otherwise, false.</returns>
    private static bool IsValidHeaderName(in ReadOnlySequence<byte> name)
    {
        // Iterate through all segments in the sequence
        foreach (ReadOnlyMemory<byte> segment in name)
        {
            foreach (byte value in segment.Span)
            {
                if (!Ascii.IsTokenByte(value))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Rejects field values containing forbidden controls while permitting tabs,
    /// printable ASCII, and opaque bytes above 0x7F.
    /// </summary>
    /// <param name="value">The header value sequence to validate.</param>
    /// <returns>true if the value is valid; otherwise, false.</returns>
    private static bool IsValidHeaderValue(in ReadOnlySequence<byte> value)
    {
        foreach (ReadOnlyMemory<byte> segment in value)
        {
            foreach (byte current in segment.Span)
            {
                if (current is (< 0x20 and not ((byte)'\t')) or 0x7f)
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Compares a ReadOnlySequence to a ReadOnlySpan for equality, ignoring ASCII case differences.
    /// </summary>
    /// <param name="sequence">The sequence to compare.</param>
    /// <param name="expected">The expected value to compare against.</param>
    /// <returns>true if the sequences are equal (case-insensitive); otherwise, false.</returns>
    private static bool SequenceEqualsIgnoreCase(
        in ReadOnlySequence<byte> sequence,
        ReadOnlySpan<byte> expected)
    {
        if (sequence.Length != expected.Length)
        {
            return false;
        }

        int index = 0;
        foreach (ReadOnlyMemory<byte> segment in sequence)
        {
            foreach (byte value in segment.Span)
            {
                byte expectedValue = expected[index++];
                byte actual = value;

                if ((uint)(actual - (byte)'A') <= 'Z' - 'A')
                {
                    actual = (byte)(actual + ('a' - 'A'));
                }

                if ((uint)(expectedValue - (byte)'A') <= 'Z' - 'A')
                {
                    expectedValue = (byte)(expectedValue + ('a' - 'A'));
                }

                if (actual != expectedValue)
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Attempts to parse a Content-Length value from a ReadOnlySequence.
    /// Handles leading/trailing whitespace and validates the numeric value.
    /// </summary>
    /// <param name="value">The value sequence to parse.</param>
    /// <param name="result">When this method returns true, contains the parsed length.</param>
    /// <returns>true if the value was successfully parsed; otherwise, false.</returns>
    private static bool TryParseContentLength(in ReadOnlySequence<byte> value, out int result)
    {
        int parsed = 0;
        bool sawDigit = false;
        bool sawTrailingWhitespace = false;

        foreach (ReadOnlyMemory<byte> segment in value)
        {
            foreach (byte current in segment.Span)
            {
                if (Ascii.IsOptionalWhitespace(current))
                {
                    if (sawDigit)
                    {
                        sawTrailingWhitespace = true;
                    }

                    continue;
                }

                // Once trailing whitespace begins, another digit would be ambiguous.
                if (sawTrailingWhitespace ||
                    current is < (byte)'0' or > (byte)'9' ||
                    parsed > (int.MaxValue - (current - '0')) / 10)
                {
                    result = 0;
                    return false;
                }

                sawDigit = true;
                parsed = (parsed * 10) + current - '0';
            }
        }

        result = parsed;
        return sawDigit;
    }
}

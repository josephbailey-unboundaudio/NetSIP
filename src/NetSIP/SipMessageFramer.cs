using System.Buffers;

namespace NetSIP;

/// <summary>Finds complete SIP messages in a possibly segmented transport buffer.</summary>
public static class SipMessageFramer
{
    private static ReadOnlySpan<byte> HeaderTerminator => "\r\n\r\n"u8;
    private static ReadOnlySpan<byte> CrLf => "\r\n"u8;

    public static SipFrameStatus TryRead(
        in ReadOnlySequence<byte> input,
        SipServerLimits limits,
        out ReadOnlySequence<byte> message)
    {
        ArgumentNullException.ThrowIfNull(limits);
        message = default;

        var reader = new SequenceReader<byte>(input);
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

        var lineReader = new SequenceReader<byte>(headerBlock);
        int lineNumber = 0;
        int headerCount = 0;
        int contentLength = 0;
        bool contentLengthSeen = false;

        while (!lineReader.End)
        {
            ReadOnlySequence<byte> line;
            if (!lineReader.TryReadTo(out line, CrLf, advancePastDelimiter: true))
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

    private static bool TryInspectHeader(
        in ReadOnlySequence<byte> line,
        ref bool contentLengthSeen,
        ref int contentLength,
        out bool invalidContentLength)
    {
        invalidContentLength = false;
        var reader = new SequenceReader<byte>(line);
        if (!reader.TryPeek(out byte first) || Ascii.IsOptionalWhitespace(first))
        {
            return true;
        }

        if (!reader.TryReadTo(out ReadOnlySequence<byte> name, (byte)':', advancePastDelimiter: true) ||
            name.IsEmpty ||
            !IsValidHeaderName(name))
        {
            return true;
        }

        ReadOnlySequence<byte> value = line.Slice(reader.Position);
        if (!IsValidHeaderValue(value))
        {
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

    private static bool IsValidHeaderName(in ReadOnlySequence<byte> name)
    {
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

    private static bool IsValidHeaderValue(in ReadOnlySequence<byte> value)
    {
        foreach (ReadOnlyMemory<byte> segment in value)
        {
            foreach (byte current in segment.Span)
            {
                if (current < 0x20 && current != (byte)'\t' || current == 0x7f)
                {
                    return false;
                }
            }
        }

        return true;
    }

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

using System.Buffers;

namespace NetSIP;

public enum SipMessageKind
{
    Request,
    Response
}

public enum SipParseError
{
    None,
    Incomplete,
    MalformedStartLine,
    MalformedHeader,
    InvalidContentLength,
    MessageTooLarge
}

public enum SipFrameStatus
{
    Complete,
    NeedMoreData,
    Malformed,
    TooLarge
}

internal readonly struct SipMessageMetadata
{
    public SipMessageMetadata(
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
        Kind = kind;
        FirstTokenOffset = firstTokenOffset;
        FirstTokenLength = firstTokenLength;
        SecondTokenOffset = secondTokenOffset;
        SecondTokenLength = secondTokenLength;
        ThirdTokenOffset = thirdTokenOffset;
        ThirdTokenLength = thirdTokenLength;
        StatusCode = statusCode;
        HeadersOffset = headersOffset;
        HeadersLength = headersLength;
        BodyOffset = bodyOffset;
        BodyLength = bodyLength;
    }

    public SipMessageKind Kind { get; }
    public int FirstTokenOffset { get; }
    public int FirstTokenLength { get; }
    public int SecondTokenOffset { get; }
    public int SecondTokenLength { get; }
    public int ThirdTokenOffset { get; }
    public int ThirdTokenLength { get; }
    public int StatusCode { get; }
    public int HeadersOffset { get; }
    public int HeadersLength { get; }
    public int BodyOffset { get; }
    public int BodyLength { get; }
}

/// <summary>
/// A borrowed, stack-only view over one complete SIP message. The view and every span
/// obtained from it are valid only while the source buffer remains valid.
/// </summary>
public readonly ref struct SipMessageView
{
    private readonly ReadOnlySpan<byte> _message;
    private readonly SipMessageMetadata _metadata;

    internal SipMessageView(ReadOnlySpan<byte> message, SipMessageMetadata metadata)
    {
        _message = message;
        _metadata = metadata;
    }

    public SipMessageKind Kind => _metadata.Kind;

    internal SipMessageMetadata Metadata => _metadata;

    public ReadOnlySpan<byte> Raw => _message;

    public ReadOnlySpan<byte> Method =>
        Kind == SipMessageKind.Request
            ? _message.Slice(_metadata.FirstTokenOffset, _metadata.FirstTokenLength)
            : [];

    public ReadOnlySpan<byte> RequestUri =>
        Kind == SipMessageKind.Request
            ? _message.Slice(_metadata.SecondTokenOffset, _metadata.SecondTokenLength)
            : [];

    public ReadOnlySpan<byte> Version =>
        Kind == SipMessageKind.Request
            ? _message.Slice(_metadata.ThirdTokenOffset, _metadata.ThirdTokenLength)
            : _message.Slice(_metadata.FirstTokenOffset, _metadata.FirstTokenLength);

    public int StatusCode => _metadata.StatusCode;

    public ReadOnlySpan<byte> ReasonPhrase =>
        Kind == SipMessageKind.Response
            ? _message.Slice(_metadata.ThirdTokenOffset, _metadata.ThirdTokenLength)
            : [];

    public ReadOnlySpan<byte> Body => _message.Slice(_metadata.BodyOffset, _metadata.BodyLength);

    public SipHeaderEnumerator GetHeaders() =>
        new(_message.Slice(_metadata.HeadersOffset, _metadata.HeadersLength));

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

/// <summary>A borrowed view over a SIP header, preserving the exact bytes after the colon.</summary>
public readonly ref struct SipHeaderView
{
    internal SipHeaderView(ReadOnlySpan<byte> name, ReadOnlySpan<byte> rawValue)
    {
        Name = name;
        RawValue = rawValue;
    }

    public ReadOnlySpan<byte> Name { get; }

    public ReadOnlySpan<byte> RawValue { get; }

    public ReadOnlySpan<byte> Value => Ascii.TrimOptionalWhitespace(RawValue);
}

/// <summary>Enumerates headers without allocating or building a header collection.</summary>
public ref struct SipHeaderEnumerator
{
    private ReadOnlySpan<byte> _remaining;
    private SipHeaderView _current;

    internal SipHeaderEnumerator(ReadOnlySpan<byte> headers)
    {
        _remaining = headers;
        _current = default;
    }

    public readonly SipHeaderView Current => _current;

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
                continue;
            }

            _current = new SipHeaderView(line[..colon], line[(colon + 1)..]);
            return true;
        }

        return false;
    }
}

internal static class Ascii
{
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

    public static bool IsOptionalWhitespace(byte value) => value is (byte)' ' or (byte)'\t';

    public static bool IsTokenByte(byte value) =>
        value is >= 0x21 and <= 0x7e &&
        value is not (byte)'(' and not (byte)')' and not (byte)'<' and not (byte)'>' and
        not (byte)'@' and not (byte)',' and not (byte)';' and not (byte)':' and
        not (byte)'\\' and not (byte)'"' and not (byte)'/' and not (byte)'[' and
        not (byte)']' and not (byte)'?' and not (byte)'=' and not (byte)'{' and not (byte)'}';
}

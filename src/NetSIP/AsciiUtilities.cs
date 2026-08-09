namespace NetSIP;

/// <summary>
/// Provides allocation-free ASCII operations used by SIP parsing and matching.
/// </summary>
internal static class AsciiUtilities
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

namespace NetSIP;

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

namespace NetSIP;

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

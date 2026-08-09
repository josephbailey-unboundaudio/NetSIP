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

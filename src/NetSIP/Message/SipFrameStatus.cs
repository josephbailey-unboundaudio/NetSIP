namespace NetSIP.Message
{
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
}

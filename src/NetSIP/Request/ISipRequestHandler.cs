namespace NetSIP.Request
{
    /// <summary>
    /// Handles one SIP message at a time. The supplied context is reused for the connection;
    /// handlers must not retain it, its message view, or any borrowed memory after completion.
    /// Implementations must observe the cancellation token so handler deadlines and shutdown
    /// can complete without violating borrowed-buffer lifetimes.
    /// </summary>
    public interface ISipRequestHandler
    {
        /// <summary>Handles one borrowed SIP message.</summary>
        /// <param name="context">
        /// The reusable connection context. It and its message must not be retained.
        /// </param>
        /// <param name="cancellationToken">The cooperative handler deadline and shutdown token.</param>
        /// <returns>An operation that completes after the handler has finished using borrowed data.</returns>
        ValueTask HandleAsync(SipRequestContext context, CancellationToken cancellationToken);
    }

}

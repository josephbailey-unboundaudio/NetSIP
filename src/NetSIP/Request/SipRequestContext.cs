using NetSIP.Message;
using NetSIP.Response;
using System.Net;

namespace NetSIP.Request
{
    /// <summary>
    /// Per-connection context exposing the current borrowed message and response writer.
    /// </summary>
    public sealed class SipRequestContext
    {
        /// <summary>
        /// The borrowed message bytes for the current request.
        /// </summary>
        private ReadOnlyMemory<byte> _message;

        /// <summary>
        /// The metadata describing offsets into the message.
        /// </summary>
        private SipMessageMetadata _metadata;

        /// <summary>
        /// Initializes a new instance of the <see cref="SipRequestContext"/> class.
        /// </summary>
        /// <param name="remoteEndPoint">The remote endpoint of the connection.</param>
        /// <param name="response">The response writer for this connection.</param>
        internal SipRequestContext(EndPoint? remoteEndPoint, SipResponseWriter response)
        {
            RemoteEndPoint = remoteEndPoint;
            Response = response;
        }

        /// <summary>
        /// Gets the remote endpoint of the connection.
        /// </summary>
        public EndPoint? RemoteEndPoint { get; }

        /// <summary>
        /// Gets the response writer for sending SIP responses.
        /// </summary>
        public SipResponseWriter Response { get; }

        /// <summary>
        /// Gets a view over the current SIP request message.
        /// The view and all spans derived from it are only valid until the handler completes.
        /// </summary>
        public SipMessageView Message => new(_message.Span, _metadata);

        /// <summary>
        /// Creates a copy of the current message bytes that the caller owns.
        /// Use this if you need to retain the message data after the handler completes.
        /// </summary>
        /// <returns>A byte array containing a copy of the current message.</returns>
        public byte[] CopyMessage()
        {
            return _message.ToArray();
        }

        /// <summary>
        /// Sets the current message and metadata.
        /// </summary>
        internal void SetMessage(ReadOnlyMemory<byte> message, in SipMessageMetadata metadata)
        {
            _message = message;
            _metadata = metadata;
        }

        /// <summary>
        /// Clears the current message, releasing the borrowed memory reference.
        /// </summary>
        internal void ClearMessage()
        {
            _message = default;
            _metadata = default;
        }
    }

}

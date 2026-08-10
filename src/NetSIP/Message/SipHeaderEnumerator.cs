namespace NetSIP.Message
{
    /// <summary>
    /// Enumerates borrowed headers without allocating. The source must remain valid
    /// for the lifetime of the enumerator.
    /// </summary>
    public ref struct SipHeaderEnumerator
    {
        /// <summary>
        /// The remaining unparsed header bytes.
        /// </summary>
        private ReadOnlySpan<byte> _remaining;

        /// <summary>
        /// Initializes a new instance of the <see cref="SipHeaderEnumerator"/> struct.
        /// </summary>
        /// <param name="headers">The complete headers section bytes to enumerate.</param>
        internal SipHeaderEnumerator(ReadOnlySpan<byte> headers)
        {
            _remaining = headers;
            Current = default;
        }

        /// <summary>
        /// Gets the current header in the enumeration.
        /// </summary>
        public SipHeaderView Current { get; private set; }

        /// <summary>
        /// Advances the enumerator to the next header.
        /// </summary>
        /// <returns>true if a valid header was found; false if no more headers remain.</returns>
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
                    // Parsed messages cannot reach this path; tolerate it for minimal error views.
                    continue;
                }

                Current = new SipHeaderView(line[..colon], line[(colon + 1)..]);
                return true;
            }

            return false;
        }
    }
}

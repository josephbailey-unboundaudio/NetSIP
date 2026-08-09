using System.Buffers;
using System.Buffers.Text;
using System.IO.Pipelines;
using System.Net;
using System.Security.Cryptography;

namespace NetSIP;

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

/// <summary>Per-connection context exposing the current borrowed message and response writer.</summary>
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

/// <summary>Writes SIP responses synchronously into a pooled pipeline buffer.</summary>
public sealed class SipResponseWriter
{
    /// <summary>
    /// Seed value for generating unique tags for To headers in responses.
    /// </summary>
    private static long s_nextTag = CreateTagSeed();

    /// <summary>
    /// The underlying pipeline writer for buffering response bytes.
    /// </summary>
    private readonly PipeWriter _writer;

    /// <summary>
    /// Initializes a new instance of the <see cref="SipResponseWriter"/> class.
    /// </summary>
    /// <param name="writer">The pipeline writer to use.</param>
    internal SipResponseWriter(PipeWriter writer)
    {
        _writer = writer;
    }

    /// <summary>
    /// Gets a value indicating whether there are pending bytes to flush.
    /// </summary>
    internal bool HasPendingBytes { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the connection should be closed after flushing.
    /// </summary>
    internal bool CloseAfterFlush { get; private set; }

    /// <summary>
    /// Writes a successful OPTIONS response (200 OK) with the server's supported methods.
    /// </summary>
    /// <param name="request">The OPTIONS request to respond to.</param>
    /// <param name="allowRegister">If true, includes REGISTER in the Allow header.</param>
    /// <param name="allowInvite">If true, includes INVITE in the Allow header.</param>
    /// <returns>true if the response was written; false if the request is not an OPTIONS request.</returns>
    public bool WriteOptionsOk(
        SipMessageView request,
        bool allowRegister = false,
        bool allowInvite = false)
    {
        return request.Kind == SipMessageKind.Request &&
            Ascii.EqualsIgnoreCase(request.Method, "OPTIONS"u8) && WriteResponseCore(
            200,
            "OK"u8,
            request,
            body: default,
            contentType: default,
            (allowRegister, allowInvite) switch
            {
                (true, true) => ResponseHeaders.OptionsRegisterAndInvite,
                (true, false) => ResponseHeaders.OptionsAndRegister,
                (false, true) => ResponseHeaders.OptionsAndInvite,
                _ => ResponseHeaders.Options
            });
    }

    /// <summary>Writes a successful REGISTER response containing the current bindings.</summary>
    /// <param name="request">The REGISTER request whose transaction headers are preserved.</param>
    /// <param name="bindings">The current owned bindings to serialize as Contact fields.</param>
    /// <returns><see langword="true"/> when the request and bindings were valid and written.</returns>
    public bool WriteRegisterOk(
        SipMessageView request,
        ReadOnlySpan<SipRegistrationBinding> bindings)
    {
        return request.Kind == SipMessageKind.Request &&
            Ascii.EqualsIgnoreCase(request.Method, "REGISTER"u8) &&
            ValidateRegistrationBindings(bindings) && WriteResponseCore(
            200,
            "OK"u8,
            request,
            body: default,
            contentType: default,
            ResponseHeaders.Register,
            bindings);
    }

    /// <summary>Writes a REGISTER 423 response with the registrar's minimum expiration.</summary>
    /// <param name="request">The REGISTER request whose transaction headers are preserved.</param>
    /// <param name="minimumExpires">The positive minimum interval in seconds.</param>
    /// <returns><see langword="true"/> when the response was written.</returns>
    public bool WriteRegisterIntervalTooBrief(SipMessageView request, int minimumExpires)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(minimumExpires);
        return WriteResponseCore(
            423,
            "Interval Too Brief"u8,
            request,
            body: default,
            contentType: default,
            ResponseHeaders.MinExpires,
            bindings: default,
            minimumExpires);
    }

    /// <summary>Writes a final response selected by an INVITE dialplan.</summary>
    /// <param name="request">The INVITE request whose transaction headers are preserved.</param>
    /// <param name="result">The owned, validated dialplan result.</param>
    /// <returns><see langword="true"/> when the request and result were valid and written.</returns>
    public bool WriteInviteResponse(
        SipMessageView request,
        SipDialPlanResult result)
    {
        return request.Kind == SipMessageKind.Request &&
            Ascii.EqualsIgnoreCase(request.Method, "INVITE"u8) &&
            result.IsValid &&
            WriteResponseCore(
                result.StatusCode,
                result.ReasonPhrase.Span,
                request,
                result.Body.Span,
                result.ContentType.Span,
                result.Contact.IsEmpty
                    ? ResponseHeaders.None
                    : ResponseHeaders.InviteContact,
                bindings: default,
                inviteContact: result.Contact.Span);
    }

    /// <summary>Writes one 401 Digest challenge per enabled algorithm.</summary>
    /// <param name="request">The request whose transaction headers are preserved.</param>
    /// <param name="realm">A printable ASCII realm without quote or backslash.</param>
    /// <param name="nonce">A printable ASCII server nonce.</param>
    /// <param name="algorithms">
    /// Flags selecting the algorithms to advertise. SHA-256 is emitted before MD5.
    /// </param>
    /// <param name="stale">Whether the prior nonce was valid but expired.</param>
    /// <returns>
    /// <see langword="true"/> when the challenge was written; otherwise,
    /// <see langword="false"/> when required request headers were unavailable.
    /// </returns>
    public bool WriteDigestChallenge(
        SipMessageView request,
        ReadOnlySpan<byte> realm,
        ReadOnlySpan<byte> nonce,
        SipDigestAlgorithms algorithms,
        bool stale = false)
    {
        if (realm.IsEmpty ||
            nonce.IsEmpty ||
            !IsSafeDigestChallengeValue(realm) ||
            !IsSafeDigestChallengeValue(nonce))
        {
            throw new ArgumentException("Digest challenge values must contain safe printable ASCII.");
        }

        _ = algorithms == SipDigestAlgorithms.None ||
            (algorithms & ~(SipDigestAlgorithms.Sha256 | SipDigestAlgorithms.Md5)) != 0
            ? throw new ArgumentOutOfRangeException(nameof(algorithms))
            : algorithms;

        return WriteResponseCore(
            401,
            "Unauthorized"u8,
            request,
            body: default,
            contentType: default,
            ResponseHeaders.DigestChallenge,
            bindings: default,
            digestRealm: realm,
            digestNonce: nonce,
            digestAlgorithms: algorithms,
            digestStale: stale);
    }

    /// <summary>
    /// Writes a response that preserves the request's transaction and dialog headers.
    /// The supplied spans are consumed before this method returns.
    /// </summary>
    /// <param name="statusCode">The response status from 100 through 699.</param>
    /// <param name="reasonPhrase">The reason phrase, without line breaks.</param>
    /// <param name="request">The request whose Via, From, To, Call-ID, and CSeq are reflected.</param>
    /// <param name="body">An optional response body.</param>
    /// <param name="contentType">The body media type, required for a non-empty body.</param>
    /// <returns>
    /// <see langword="true"/> when required safe transaction headers were available;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    public bool WriteResponse(
        int statusCode,
        ReadOnlySpan<byte> reasonPhrase,
        SipMessageView request,
        ReadOnlySpan<byte> body = default,
        ReadOnlySpan<byte> contentType = default)
    {
        return WriteResponseCore(
            statusCode,
            reasonPhrase,
            request,
            body,
            contentType,
            ResponseHeaders.None,
            bindings: default);
    }

    /// <summary>
    /// Core method for writing a SIP response that preserves transaction and dialog headers from the request.
    /// </summary>
    /// <param name="statusCode">The numeric status code (100-699).</param>
    /// <param name="reasonPhrase">The human-readable reason phrase.</param>
    /// <param name="request">The request being responded to.</param>
    /// <param name="body">The optional response body.</param>
    /// <param name="contentType">The Content-Type for the body.</param>
    /// <param name="responseHeaders">Additional headers to include.</param>
    /// <param name="bindings">Registration bindings for REGISTER responses.</param>
    /// <param name="minimumExpires">Minimum expiration for 423 responses.</param>
    /// <param name="inviteContact">Contact selected by an INVITE dialplan.</param>
    /// <param name="digestRealm">Realm for a Digest challenge.</param>
    /// <param name="digestNonce">Nonce for a Digest challenge.</param>
    /// <param name="digestAlgorithms">Algorithms advertised by a Digest challenge.</param>
    /// <param name="digestStale">Whether a Digest challenge replaces an expired nonce.</param>
    /// <returns>true if the response was written; false if the request was invalid.</returns>
    private bool WriteResponseCore(
        int statusCode,
        ReadOnlySpan<byte> reasonPhrase,
        SipMessageView request,
        ReadOnlySpan<byte> body,
        ReadOnlySpan<byte> contentType,
        ResponseHeaders responseHeaders,
        ReadOnlySpan<SipRegistrationBinding> bindings = default,
        int minimumExpires = 0,
        ReadOnlySpan<byte> inviteContact = default,
        ReadOnlySpan<byte> digestRealm = default,
        ReadOnlySpan<byte> digestNonce = default,
        SipDigestAlgorithms digestAlgorithms = SipDigestAlgorithms.None,
        bool digestStale = false)
    {
        if (statusCode is < 100 or > 699)
        {
            throw new ArgumentOutOfRangeException(nameof(statusCode));
        }

        if (ContainsLineBreak(reasonPhrase) || ContainsLineBreak(contentType))
        {
            throw new ArgumentException("Response reason phrases and content types cannot contain line breaks.");
        }

        if (request.Kind != SipMessageKind.Request)
        {
            return false;
        }

        // Validate that required headers exist and are safe to reflect
        bool hasVia = false;
        bool hasFrom = false;
        bool hasTo = false;
        bool hasCallId = false;
        bool hasCSeq = false;

        SipHeaderEnumerator validationHeaders = request.GetHeaders();
        while (validationHeaders.MoveNext())
        {
            SipHeaderView header = validationHeaders.Current;
            ReadOnlySpan<byte> name = header.Name;
            if ((IsVia(name) || IsFrom(name) || IsTo(name) || IsCallId(name) || IsCSeq(name)) &&
                !IsSafeReflectedValue(header.RawValue))
            {
                return false;
            }

            hasVia |= IsVia(name);
            hasFrom |= IsFrom(name);
            hasTo |= IsTo(name);
            hasCallId |= IsCallId(name);
            hasCSeq |= IsCSeq(name);
        }

        if (!hasVia || !hasFrom || !hasTo || !hasCallId || !hasCSeq)
        {
            return false;
        }

        // Write status line
        Write("SIP/2.0 "u8);
        Span<byte> status =
        [
            (byte)('0' + (statusCode / 100)),
            (byte)('0' + (statusCode / 10 % 10)),
            (byte)('0' + (statusCode % 10)),
        ];
        Write(status);
        Write(" "u8);
        Write(reasonPhrase);
        Write("\r\n"u8);

        // Copy Via headers from request
        SipHeaderEnumerator headers = request.GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (IsVia(header.Name))
            {
                WriteHeader("Via:"u8, header.RawValue);
            }
        }

        // Generate a unique tag for the To header
        Span<byte> generatedTag = stackalloc byte[16];
        ulong tagValue = unchecked((ulong)Interlocked.Increment(ref s_nextTag));
        if (!Utf8Formatter.TryFormat(tagValue, generatedTag, out int tagLength, new StandardFormat('x', 16)))
        {
            throw new InvalidOperationException("Unable to format the response To tag.");
        }

        // Write transaction/dialog headers
        WriteSingleHeader(request, HeaderKind.From, "From:"u8, generatedTag[..tagLength]);
        WriteSingleHeader(request, HeaderKind.To, "To:"u8, generatedTag[..tagLength]);
        WriteSingleHeader(request, HeaderKind.CallId, "Call-ID:"u8, generatedTag[..tagLength]);
        WriteSingleHeader(request, HeaderKind.CSeq, "CSeq:"u8, generatedTag[..tagLength]);
        WriteAdditionalHeaders(
            responseHeaders,
            bindings,
            minimumExpires,
            inviteContact,
            digestRealm,
            digestNonce,
            digestAlgorithms,
            digestStale);
        if (!contentType.IsEmpty)
        {
            Write("Content-Type: "u8);
            Write(contentType);
            Write("\r\n"u8);
        }

        // Write Content-Length and body
        Write("Content-Length: "u8);
        Span<byte> length = stackalloc byte[10];
        if (!Utf8Formatter.TryFormat(body.Length, length, out int written))
        {
            throw new InvalidOperationException("Unable to format the response body length.");
        }

        Write(length[..written]);
        Write("\r\n\r\n"u8);
        Write(body);
        HasPendingBytes = true;
        CloseAfterFlush = false;
        return true;
    }

    /// <summary>
    /// Writes a simple error response and marks the connection for closure.
    /// Used for protocol-level errors where no request context is available.
    /// </summary>
    /// <param name="statusCode">The SIP status code (400, 408, 500, 501, or 513).</param>
    public void WriteError(int statusCode)
    {
        ReadOnlySpan<byte> status = statusCode switch
        {
            400 => "SIP/2.0 400 Bad Request\r\n"u8,
            408 => "SIP/2.0 408 Request Timeout\r\n"u8,
            500 => "SIP/2.0 500 Server Internal Error\r\n"u8,
            501 => "SIP/2.0 501 Not Implemented\r\n"u8,
            513 => "SIP/2.0 513 Message Too Large\r\n"u8,
            _ => throw new ArgumentOutOfRangeException(nameof(statusCode))
        };

        Write(status);
        Write("Content-Length: 0\r\nConnection: close\r\n\r\n"u8);
        HasPendingBytes = true;
        CloseAfterFlush = true;
    }

    /// <summary>
    /// Flushes pending bytes to the underlying transport.
    /// </summary>
    internal ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken)
    {
        HasPendingBytes = false;
        return _writer.FlushAsync(cancellationToken);
    }

    /// <summary>
    /// Resets the close-after-flush flag, allowing the connection to remain open.
    /// </summary>
    internal void ResetAfterFlush()
    {
        CloseAfterFlush = false;
    }

    /// <summary>
    /// Forces the connection to close after the next flush.
    /// </summary>
    internal void ForceCloseAfterFlush()
    {
        CloseAfterFlush = true;
    }

    /// <summary>
    /// Writes a response and marks the connection for closure after flushing.
    /// </summary>
    internal bool WriteResponseAndClose(
        int statusCode,
        ReadOnlySpan<byte> reasonPhrase,
        SipMessageView request)
    {
        bool written = WriteResponseCore(
            statusCode,
            reasonPhrase,
            request,
            body: default,
            contentType: default,
            ResponseHeaders.ConnectionClose,
            bindings: default);
        CloseAfterFlush = written;
        return written;
    }

    /// <summary>
    /// Writes a single header from the request to the response, optionally adding a tag parameter.
    /// </summary>
    private void WriteSingleHeader(
        SipMessageView request,
        HeaderKind kind,
        ReadOnlySpan<byte> serializedName,
        ReadOnlySpan<byte> generatedTag)
    {
        SipHeaderEnumerator headers = request.GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (!Matches(kind, header.Name))
            {
                continue;
            }

            Write(serializedName);
            Write(header.RawValue);
            // Add tag parameter to To header if not present
            if (kind == HeaderKind.To && !ContainsTagParameter(header.Value))
            {
                Write(";tag="u8);
                Write(generatedTag);
            }

            Write("\r\n"u8);
            return;
        }
    }

    /// <summary>
    /// Writes a complete header line with name and value.
    /// </summary>
    private void WriteHeader(ReadOnlySpan<byte> name, ReadOnlySpan<byte> rawValue)
    {
        Write(name);
        Write(rawValue);
        Write("\r\n"u8);
    }

    /// <summary>
    /// Writes raw bytes to the underlying pipeline writer.
    /// </summary>
    private void Write(ReadOnlySpan<byte> value)
    {
        Span<byte> destination = _writer.GetSpan(value.Length);
        value.CopyTo(destination);
        _writer.Advance(value.Length);
    }

    /// <summary>
    /// Writes protocol-specific additional headers based on the response type.
    /// </summary>
    private void WriteAdditionalHeaders(
        ResponseHeaders responseHeaders,
        ReadOnlySpan<SipRegistrationBinding> bindings,
        int minimumExpires,
        ReadOnlySpan<byte> inviteContact,
        ReadOnlySpan<byte> digestRealm,
        ReadOnlySpan<byte> digestNonce,
        SipDigestAlgorithms digestAlgorithms,
        bool digestStale)
    {
        switch (responseHeaders)
        {
            case ResponseHeaders.None:
                return;
            case ResponseHeaders.Options:
                Write("Allow: OPTIONS\r\n"u8);
                return;
            case ResponseHeaders.OptionsAndRegister:
                Write("Allow: OPTIONS, REGISTER\r\n"u8);
                return;
            case ResponseHeaders.OptionsAndInvite:
                Write("Allow: OPTIONS, INVITE\r\n"u8);
                return;
            case ResponseHeaders.OptionsRegisterAndInvite:
                Write("Allow: OPTIONS, REGISTER, INVITE\r\n"u8);
                return;
            case ResponseHeaders.ConnectionClose:
                Write("Connection: close\r\n"u8);
                return;
            case ResponseHeaders.Register:
                // Write Contact headers for each binding
                Span<byte> expiration = stackalloc byte[10];
                foreach (SipRegistrationBinding binding in bindings)
                {
                    if (binding.Contact.IsEmpty || binding.Expires < 0)
                    {
                        throw new ArgumentException(
                            "Registration bindings require a Contact value and non-negative expiration.",
                            nameof(bindings));
                    }

                    Write("Contact: "u8);
                    Write(binding.Contact.Span);
                    Write(";expires="u8);
                    if (!Utf8Formatter.TryFormat(binding.Expires, expiration, out int written))
                    {
                        throw new InvalidOperationException("Unable to format the binding expiration.");
                    }

                    Write(expiration[..written]);
                    Write("\r\n"u8);
                }

                return;
            case ResponseHeaders.MinExpires:
                // Write Min-Expires header for 423 responses
                Write("Min-Expires: "u8);
                Span<byte> minimum = stackalloc byte[10];
                if (!Utf8Formatter.TryFormat(minimumExpires, minimum, out int minimumLength))
                {
                    throw new InvalidOperationException("Unable to format the minimum expiration.");
                }

                Write(minimum[..minimumLength]);
                Write("\r\n"u8);
                return;
            case ResponseHeaders.InviteContact:
                Write("Contact: "u8);
                Write(inviteContact);
                Write("\r\n"u8);
                return;
            case ResponseHeaders.DigestChallenge:
                if ((digestAlgorithms & SipDigestAlgorithms.Sha256) != 0)
                {
                    WriteDigestChallengeHeader(
                        digestRealm,
                        digestNonce,
                        "SHA-256"u8,
                        digestStale);
                }

                if ((digestAlgorithms & SipDigestAlgorithms.Md5) != 0)
                {
                    WriteDigestChallengeHeader(
                        digestRealm,
                        digestNonce,
                        "MD5"u8,
                        digestStale);
                }

                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(responseHeaders));
        }
    }

    private void WriteDigestChallengeHeader(
        ReadOnlySpan<byte> realm,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> algorithm,
        bool stale)
    {
        Write("WWW-Authenticate: Digest realm=\""u8);
        Write(realm);
        Write("\", nonce=\""u8);
        Write(nonce);
        Write("\", algorithm="u8);
        Write(algorithm);
        Write(", qop=\"auth\", charset=UTF-8"u8);
        if (stale)
        {
            Write(", stale=true"u8);
        }

        Write("\r\n"u8);
    }

    private static bool IsSafeDigestChallengeValue(ReadOnlySpan<byte> value)
    {
        foreach (byte current in value)
        {
            if (current is < 0x20 or >= 0x7f or (byte)'"' or (byte)'\\')
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Checks if a header name matches Via (including compact form 'v').
    /// </summary>
    private static bool IsVia(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "Via"u8) || Ascii.EqualsIgnoreCase(name, "v"u8);
    }

    /// <summary>
    /// Checks if a header name matches From (including compact form 'f').
    /// </summary>
    private static bool IsFrom(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "From"u8) || Ascii.EqualsIgnoreCase(name, "f"u8);
    }

    /// <summary>
    /// Checks if a header name matches To (including compact form 't').
    /// </summary>
    private static bool IsTo(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "To"u8) || Ascii.EqualsIgnoreCase(name, "t"u8);
    }

    /// <summary>
    /// Checks if a header name matches Call-ID (including compact form 'i').
    /// </summary>
    private static bool IsCallId(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "Call-ID"u8) || Ascii.EqualsIgnoreCase(name, "i"u8);
    }

    /// <summary>
    /// Checks if a header name matches CSeq.
    /// </summary>
    private static bool IsCSeq(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "CSeq"u8);
    }

    /// <summary>
    /// Checks if a header name matches the specified header kind.
    /// </summary>
    private static bool Matches(HeaderKind kind, ReadOnlySpan<byte> name)
    {
        return kind switch
        {
            HeaderKind.From => IsFrom(name),
            HeaderKind.To => IsTo(name),
            HeaderKind.CallId => IsCallId(name),
            HeaderKind.CSeq => IsCSeq(name),
            _ => false
        };
    }

    /// <summary>
    /// Checks if a header value contains a 'tag' parameter.
    /// Properly handles quoted strings and angle brackets.
    /// </summary>
    private static bool ContainsTagParameter(ReadOnlySpan<byte> value)
    {
        bool quoted = false;
        bool escaped = false;
        int angleDepth = 0;
        for (int i = 0; i < value.Length; i++)
        {
            byte current = value[i];

            // Handle quoted strings
            if (quoted)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (current == (byte)'\\')
                {
                    escaped = true;
                }
                else if (current == (byte)'"')
                {
                    quoted = false;
                }

                continue;
            }

            if (current == (byte)'"')
            {
                quoted = true;
                continue;
            }

            // Track angle bracket depth
            if (current == (byte)'<')
            {
                angleDepth++;
                continue;
            }

            if (current == (byte)'>' && angleDepth > 0)
            {
                angleDepth--;
                continue;
            }

            // Look for semicolon outside angle brackets
            if (current != (byte)';' || angleDepth != 0)
            {
                continue;
            }

            // Check if this is a 'tag' parameter
            int cursor = i + 1;
            while (cursor < value.Length && Ascii.IsOptionalWhitespace(value[cursor]))
            {
                cursor++;
            }

            if (cursor + 3 > value.Length ||
                !Ascii.EqualsIgnoreCase(value.Slice(cursor, 3), "tag"u8))
            {
                continue;
            }

            cursor += 3;
            while (cursor < value.Length && Ascii.IsOptionalWhitespace(value[cursor]))
            {
                cursor++;
            }

            if (cursor < value.Length && value[cursor] == (byte)'=')
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Validates that a value is safe to reflect back in a response.
    /// Ensures it contains no control characters that could corrupt the response.
    /// </summary>
    private static bool IsSafeReflectedValue(ReadOnlySpan<byte> value)
    {
        foreach (byte current in value)
        {
            if (current is (< 0x20 and not ((byte)'\t')) or 0x7f)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Validates that registration bindings are safe to include in a response.
    /// </summary>
    private static bool ValidateRegistrationBindings(
        ReadOnlySpan<SipRegistrationBinding> bindings)
    {
        foreach (SipRegistrationBinding binding in bindings)
        {
            ReadOnlySpan<byte> contact = binding.Contact.Span;
            // Reject empty, wildcard, invalid expiration, or unsafe contacts
            if (contact.IsEmpty ||
                contact.SequenceEqual("*"u8) ||
                binding.Expires < 0 ||
                !IsSafeReflectedValue(contact))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Checks if a value contains line break characters (CR or LF).
    /// </summary>
    private static bool ContainsLineBreak(ReadOnlySpan<byte> value)
    {
        return value.IndexOfAny((byte)'\r', (byte)'\n') >= 0;
    }

    /// <summary>
    /// Creates a cryptographically random seed for tag generation.
    /// </summary>
    private static long CreateTagSeed()
    {
        Span<byte> seed = stackalloc byte[sizeof(long)];
        RandomNumberGenerator.Fill(seed);
        return BitConverter.ToInt64(seed);
    }

    /// <summary>
    /// Identifies specific SIP header types for efficient matching.
    /// </summary>
    private enum HeaderKind
    {
        /// <summary>From header.</summary>
        From,
        /// <summary>To header.</summary>
        To,
        /// <summary>Call-ID header.</summary>
        CallId,
        /// <summary>CSeq header.</summary>
        CSeq
    }

    /// <summary>
    /// Specifies which additional headers to include in a response.
    /// </summary>
    private enum ResponseHeaders
    {
        /// <summary>No additional headers.</summary>
        None,
        /// <summary>Allow: OPTIONS.</summary>
        Options,
        /// <summary>Allow: OPTIONS, REGISTER.</summary>
        OptionsAndRegister,
        /// <summary>Allow: OPTIONS, INVITE.</summary>
        OptionsAndInvite,
        /// <summary>Allow: OPTIONS, REGISTER, INVITE.</summary>
        OptionsRegisterAndInvite,
        /// <summary>Contact headers with expiration.</summary>
        Register,
        /// <summary>Min-Expires header.</summary>
        MinExpires,
        /// <summary>Contact selected by an INVITE dialplan.</summary>
        InviteContact,
        /// <summary>One WWW-Authenticate header per enabled Digest algorithm.</summary>
        DigestChallenge,
        /// <summary>Connection: close.</summary>
        ConnectionClose
    }
}

/// <summary>Responds to OPTIONS and optional REGISTER/INVITE requests.</summary>
public sealed class DefaultSipRequestHandler : ISipRequestHandler
{
    /// <summary>
    /// Optional registration handler for REGISTER requests.
    /// </summary>
    private readonly RegisterSipRequestHandler? _registerHandler;
    /// <summary>
    /// Optional dialplan handler for INVITE requests.
    /// </summary>
    private readonly SipInviteRequestHandler? _inviteHandler;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultSipRequestHandler"/> class
    /// that handles only OPTIONS requests.
    /// </summary>
    public DefaultSipRequestHandler()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultSipRequestHandler"/> class
    /// that handles OPTIONS and REGISTER requests.
    /// </summary>
    /// <param name="registerHandler">The handler for REGISTER requests.</param>
    public DefaultSipRequestHandler(RegisterSipRequestHandler registerHandler)
        : this(
            registerHandler ?? throw new ArgumentNullException(nameof(registerHandler)),
            inviteHandler: null)
    {
    }

    /// <summary>Initializes a handler that supports OPTIONS and INVITE.</summary>
    /// <param name="inviteHandler">The handler for INVITE requests.</param>
    public DefaultSipRequestHandler(SipInviteRequestHandler inviteHandler)
        : this(
            registerHandler: null,
            inviteHandler ?? throw new ArgumentNullException(nameof(inviteHandler)))
    {
    }

    /// <summary>Initializes a handler with optional REGISTER and INVITE support.</summary>
    /// <param name="registerHandler">The optional handler for REGISTER requests.</param>
    /// <param name="inviteHandler">The optional handler for INVITE requests.</param>
    public DefaultSipRequestHandler(
        RegisterSipRequestHandler? registerHandler,
        SipInviteRequestHandler? inviteHandler)
    {
        _registerHandler = registerHandler;
        _inviteHandler = inviteHandler;
    }

    /// <summary>
    /// Handles a SIP request by routing it to the appropriate handler.
    /// Supports OPTIONS and optionally REGISTER and INVITE. Rejects other methods with 501.
    /// </summary>
    /// <param name="context">The request context.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The selected handler operation.</returns>
    public ValueTask HandleAsync(SipRequestContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SipMessageView message = context.Message;

        if (Ascii.EqualsIgnoreCase(message.Method, "OPTIONS"u8))
        {
            if (!context.Response.WriteOptionsOk(
                    message,
                    allowRegister: _registerHandler is not null,
                    allowInvite: _inviteHandler is not null))
            {
                context.Response.WriteError(400);
            }
        }
        else if (_registerHandler is not null &&
            Ascii.EqualsIgnoreCase(message.Method, "REGISTER"u8))
        {
            _registerHandler.Handle(context, message);
        }
        else if (_inviteHandler is not null &&
            Ascii.EqualsIgnoreCase(message.Method, "INVITE"u8))
        {
            return _inviteHandler.HandleAsync(context, cancellationToken);
        }
        else if (!context.Response.WriteResponse(501, "Not Implemented"u8, message))
        {
            context.Response.WriteError(400);
        }

        return ValueTask.CompletedTask;
    }
}

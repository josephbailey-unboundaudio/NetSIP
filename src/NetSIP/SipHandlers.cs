using System.Buffers;
using System.Buffers.Text;
using System.Net;
using System.IO.Pipelines;
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
    ValueTask HandleAsync(SipRequestContext context, CancellationToken cancellationToken);
}

/// <summary>Per-connection context exposing the current borrowed message and response writer.</summary>
public sealed class SipRequestContext
{
    private ReadOnlyMemory<byte> _message;
    private SipMessageMetadata _metadata;

    internal SipRequestContext(EndPoint? remoteEndPoint, SipResponseWriter response)
    {
        RemoteEndPoint = remoteEndPoint;
        Response = response;
    }

    public EndPoint? RemoteEndPoint { get; }

    public SipResponseWriter Response { get; }

    public SipMessageView Message => new(_message.Span, _metadata);

    public byte[] CopyMessage() => _message.ToArray();

    internal void SetMessage(ReadOnlyMemory<byte> message, in SipMessageMetadata metadata)
    {
        _message = message;
        _metadata = metadata;
    }

    internal void ClearMessage()
    {
        _message = default;
        _metadata = default;
    }
}

/// <summary>Writes SIP responses synchronously into a pooled pipeline buffer.</summary>
public sealed class SipResponseWriter
{
    private static long s_nextTag = CreateTagSeed();
    private readonly PipeWriter _writer;

    internal SipResponseWriter(PipeWriter writer)
    {
        _writer = writer;
    }

    internal bool HasPendingBytes { get; private set; }

    internal bool CloseAfterFlush { get; private set; }

    public bool WriteOptionsOk(SipMessageView request, bool allowRegister = false)
    {
        if (request.Kind != SipMessageKind.Request ||
            !Ascii.EqualsIgnoreCase(request.Method, "OPTIONS"u8))
        {
            return false;
        }

        return WriteResponseCore(
            200,
            "OK"u8,
            request,
            body: default,
            contentType: default,
            allowRegister
                ? ResponseHeaders.OptionsAndRegister
                : ResponseHeaders.Options);
    }

    /// <summary>Writes a successful REGISTER response containing the current bindings.</summary>
    public bool WriteRegisterOk(
        SipMessageView request,
        ReadOnlySpan<SipRegistrationBinding> bindings)
    {
        if (request.Kind != SipMessageKind.Request ||
            !Ascii.EqualsIgnoreCase(request.Method, "REGISTER"u8) ||
            !ValidateRegistrationBindings(bindings))
        {
            return false;
        }

        return WriteResponseCore(
            200,
            "OK"u8,
            request,
            body: default,
            contentType: default,
            ResponseHeaders.Register,
            bindings);
    }

    /// <summary>Writes a REGISTER 423 response with the registrar's minimum expiration.</summary>
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

    /// <summary>
    /// Writes a response that preserves the request's transaction and dialog headers.
    /// The supplied spans are consumed before this method returns.
    /// </summary>
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

    private bool WriteResponseCore(
        int statusCode,
        ReadOnlySpan<byte> reasonPhrase,
        SipMessageView request,
        ReadOnlySpan<byte> body,
        ReadOnlySpan<byte> contentType,
        ResponseHeaders responseHeaders,
        ReadOnlySpan<SipRegistrationBinding> bindings = default,
        int minimumExpires = 0)
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

        Write("SIP/2.0 "u8);
        Span<byte> status = stackalloc byte[3];
        status[0] = (byte)('0' + (statusCode / 100));
        status[1] = (byte)('0' + ((statusCode / 10) % 10));
        status[2] = (byte)('0' + (statusCode % 10));
        Write(status);
        Write(" "u8);
        Write(reasonPhrase);
        Write("\r\n"u8);

        SipHeaderEnumerator headers = request.GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (IsVia(header.Name))
            {
                WriteHeader("Via:"u8, header.RawValue);
            }
        }

        Span<byte> generatedTag = stackalloc byte[16];
        ulong tagValue = unchecked((ulong)Interlocked.Increment(ref s_nextTag));
        if (!Utf8Formatter.TryFormat(tagValue, generatedTag, out int tagLength, new StandardFormat('x', 16)))
        {
            throw new InvalidOperationException("Unable to format the response To tag.");
        }

        WriteSingleHeader(request, HeaderKind.From, "From:"u8, generatedTag[..tagLength]);
        WriteSingleHeader(request, HeaderKind.To, "To:"u8, generatedTag[..tagLength]);
        WriteSingleHeader(request, HeaderKind.CallId, "Call-ID:"u8, generatedTag[..tagLength]);
        WriteSingleHeader(request, HeaderKind.CSeq, "CSeq:"u8, generatedTag[..tagLength]);
        WriteAdditionalHeaders(responseHeaders, bindings, minimumExpires);
        if (!contentType.IsEmpty)
        {
            Write("Content-Type: "u8);
            Write(contentType);
            Write("\r\n"u8);
        }

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

    internal ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken)
    {
        HasPendingBytes = false;
        return _writer.FlushAsync(cancellationToken);
    }

    internal void ResetAfterFlush() => CloseAfterFlush = false;

    internal void ForceCloseAfterFlush() => CloseAfterFlush = true;

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
            if (kind == HeaderKind.To && !ContainsTagParameter(header.Value))
            {
                Write(";tag="u8);
                Write(generatedTag);
            }

            Write("\r\n"u8);
            return;
        }
    }

    private void WriteHeader(ReadOnlySpan<byte> name, ReadOnlySpan<byte> rawValue)
    {
        Write(name);
        Write(rawValue);
        Write("\r\n"u8);
    }

    private void Write(ReadOnlySpan<byte> value)
    {
        Span<byte> destination = _writer.GetSpan(value.Length);
        value.CopyTo(destination);
        _writer.Advance(value.Length);
    }

    private void WriteAdditionalHeaders(
        ResponseHeaders responseHeaders,
        ReadOnlySpan<SipRegistrationBinding> bindings,
        int minimumExpires)
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
            case ResponseHeaders.ConnectionClose:
                Write("Connection: close\r\n"u8);
                return;
            case ResponseHeaders.Register:
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
                Write("Min-Expires: "u8);
                Span<byte> minimum = stackalloc byte[10];
                if (!Utf8Formatter.TryFormat(minimumExpires, minimum, out int minimumLength))
                {
                    throw new InvalidOperationException("Unable to format the minimum expiration.");
                }

                Write(minimum[..minimumLength]);
                Write("\r\n"u8);
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(responseHeaders));
        }
    }

    private static bool IsVia(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "Via"u8) || Ascii.EqualsIgnoreCase(name, "v"u8);

    private static bool IsFrom(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "From"u8) || Ascii.EqualsIgnoreCase(name, "f"u8);

    private static bool IsTo(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "To"u8) || Ascii.EqualsIgnoreCase(name, "t"u8);

    private static bool IsCallId(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "Call-ID"u8) || Ascii.EqualsIgnoreCase(name, "i"u8);

    private static bool IsCSeq(ReadOnlySpan<byte> name) => Ascii.EqualsIgnoreCase(name, "CSeq"u8);

    private static bool Matches(HeaderKind kind, ReadOnlySpan<byte> name) =>
        kind switch
        {
            HeaderKind.From => IsFrom(name),
            HeaderKind.To => IsTo(name),
            HeaderKind.CallId => IsCallId(name),
            HeaderKind.CSeq => IsCSeq(name),
            _ => false
        };

    private static bool ContainsTagParameter(ReadOnlySpan<byte> value)
    {
        bool quoted = false;
        bool escaped = false;
        int angleDepth = 0;
        for (int i = 0; i < value.Length; i++)
        {
            byte current = value[i];
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

            if (current != (byte)';' || angleDepth != 0)
            {
                continue;
            }

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

    private static bool IsSafeReflectedValue(ReadOnlySpan<byte> value)
    {
        foreach (byte current in value)
        {
            if (current < 0x20 && current != (byte)'\t' || current == 0x7f)
            {
                return false;
            }
        }

        return true;
    }

    private static bool ValidateRegistrationBindings(
        ReadOnlySpan<SipRegistrationBinding> bindings)
    {
        foreach (SipRegistrationBinding binding in bindings)
        {
            ReadOnlySpan<byte> contact = binding.Contact.Span;
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

    private static bool ContainsLineBreak(ReadOnlySpan<byte> value) =>
        value.IndexOfAny((byte)'\r', (byte)'\n') >= 0;

    private static long CreateTagSeed()
    {
        Span<byte> seed = stackalloc byte[sizeof(long)];
        RandomNumberGenerator.Fill(seed);
        return BitConverter.ToInt64(seed);
    }

    private enum HeaderKind
    {
        From,
        To,
        CallId,
        CSeq
    }

    private enum ResponseHeaders
    {
        None,
        Options,
        OptionsAndRegister,
        Register,
        MinExpires,
        ConnectionClose
    }
}

/// <summary>Responds to OPTIONS and REGISTER, and rejects other methods with 501.</summary>
public sealed class DefaultSipRequestHandler : ISipRequestHandler
{
    private readonly RegisterSipRequestHandler? _registerHandler;

    public DefaultSipRequestHandler()
    {
    }

    public DefaultSipRequestHandler(RegisterSipRequestHandler registerHandler)
    {
        ArgumentNullException.ThrowIfNull(registerHandler);
        _registerHandler = registerHandler;
    }

    public ValueTask HandleAsync(SipRequestContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SipMessageView message = context.Message;
        if (Ascii.EqualsIgnoreCase(message.Method, "OPTIONS"u8))
        {
            if (!context.Response.WriteOptionsOk(
                    message,
                    allowRegister: _registerHandler is not null))
            {
                context.Response.WriteError(400);
            }
        }
        else if (_registerHandler is not null &&
            Ascii.EqualsIgnoreCase(message.Method, "REGISTER"u8))
        {
            _registerHandler.Handle(context, message);
        }
        else if (!context.Response.WriteResponse(501, "Not Implemented"u8, message))
        {
            context.Response.WriteError(400);
        }

        return ValueTask.CompletedTask;
    }
}

using System.Net;
using System.Text;

namespace NetSIP;

/// <summary>A borrowed INVITE context valid only while the processor call is active.</summary>
public readonly struct SipInviteContext
{
    private readonly SipRequestContext _requestContext;

    internal SipInviteContext(SipRequestContext requestContext)
    {
        _requestContext = requestContext;
    }

    /// <summary>Gets the remote peer for the current connection, when available.</summary>
    public EndPoint? RemoteEndPoint => _requestContext.RemoteEndPoint;

    /// <summary>
    /// Gets the borrowed INVITE message. The view must not be retained after
    /// <see cref="ISipDialPlanProcessor.ProcessAsync"/> completes.
    /// </summary>
    public SipMessageView Request => _requestContext.Message;
}

/// <summary>Selects a final response for an INVITE request.</summary>
public interface ISipDialPlanProcessor
{
    /// <summary>Selects the final response for an INVITE request.</summary>
    /// <param name="context">The borrowed INVITE context.</param>
    /// <param name="cancellationToken">A token that cancels routing work.</param>
    /// <returns>An owned dialplan result.</returns>
    ValueTask<SipDialPlanResult> ProcessAsync(
        SipInviteContext context,
        CancellationToken cancellationToken);
}

/// <summary>An owned final INVITE response selected by a dialplan.</summary>
public readonly struct SipDialPlanResult
{
    private SipDialPlanResult(
        int statusCode,
        ReadOnlyMemory<byte> reasonPhrase,
        ReadOnlyMemory<byte> contact,
        ReadOnlyMemory<byte> body,
        ReadOnlyMemory<byte> contentType)
    {
        StatusCode = statusCode;
        ReasonPhrase = reasonPhrase;
        Contact = contact;
        Body = body;
        ContentType = contentType;
    }

    /// <summary>Gets the final SIP status code.</summary>
    public int StatusCode { get; }

    /// <summary>Gets the reason phrase bytes.</summary>
    public ReadOnlyMemory<byte> ReasonPhrase { get; }

    /// <summary>Gets the Contact header value for successful or redirect responses.</summary>
    public ReadOnlyMemory<byte> Contact { get; }

    /// <summary>Gets the optional response body.</summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>Gets the Content-Type header value for the response body.</summary>
    public ReadOnlyMemory<byte> ContentType { get; }

    internal bool IsValid =>
        StatusCode is >= 200 and <= 699 &&
        !ReasonPhrase.IsEmpty &&
        IsSafeHeaderValue(ReasonPhrase.Span) &&
        IsSafeHeaderValue(Contact.Span) &&
        IsSafeHeaderValue(ContentType.Span) &&
        (Body.IsEmpty || !ContentType.IsEmpty) &&
        (StatusCode < 400 ? !Contact.IsEmpty : Contact.IsEmpty);

    /// <summary>Creates a 200 response with a Contact and optional body.</summary>
    public static SipDialPlanResult Answer(
        ReadOnlyMemory<byte> contact,
        ReadOnlyMemory<byte> body = default,
        ReadOnlyMemory<byte> contentType = default)
    {
        return new(200, "OK"u8.ToArray(), contact, body, contentType);
    }

    /// <summary>Creates a redirect response with a Contact.</summary>
    public static SipDialPlanResult Redirect(
        ReadOnlyMemory<byte> contact,
        int statusCode = 302,
        ReadOnlyMemory<byte> reasonPhrase = default)
    {
        return new(
            statusCode,
            reasonPhrase.IsEmpty ? "Moved Temporarily"u8.ToArray() : reasonPhrase,
            contact,
            body: default,
            contentType: default);
    }

    /// <summary>Creates a final rejection response without a Contact.</summary>
    public static SipDialPlanResult Reject(
        int statusCode,
        ReadOnlyMemory<byte> reasonPhrase)
    {
        return new(
            statusCode,
            reasonPhrase,
            contact: default,
            body: default,
            contentType: default);
    }

    private static bool IsSafeHeaderValue(ReadOnlySpan<byte> value)
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
}

/// <summary>A prefix rule used by <see cref="PrefixSipDialPlanProcessor"/>.</summary>
public sealed class SipDialPlanRule
{
    private readonly byte[] _prefix;

    /// <summary>Initializes a rule for a request-URI user prefix.</summary>
    public SipDialPlanRule(string prefix, SipDialPlanResult result)
    {
        ArgumentNullException.ThrowIfNull(prefix);
        if (!prefix.All(static value => value is >= '!' and <= '~' and not '@' and not ';' and not '?'))
        {
            throw new ArgumentException("Dialplan prefixes must contain visible URI user characters.", nameof(prefix));
        }

        _prefix = Encoding.ASCII.GetBytes(prefix);
        Result = result;
    }

    /// <summary>Gets the response selected by this rule.</summary>
    public SipDialPlanResult Result { get; }

    internal ReadOnlySpan<byte> Prefix => _prefix;
}

/// <summary>Selects the longest matching request-URI user prefix.</summary>
public sealed class PrefixSipDialPlanProcessor : ISipDialPlanProcessor
{
    private readonly SipDialPlanRule[] _rules;
    private readonly SipDialPlanResult _defaultResult;

    /// <summary>Initializes a longest-prefix dialplan.</summary>
    public PrefixSipDialPlanProcessor(
        IEnumerable<SipDialPlanRule> rules,
        SipDialPlanResult defaultResult)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _rules =
        [
            .. rules.OrderByDescending(static rule => rule.Prefix.Length)
        ];
        if (_rules.Any(static rule => !rule.Result.IsValid) ||
            !defaultResult.IsValid)
        {
            throw new ArgumentException("Dialplan results must be valid final SIP responses.");
        }

        _defaultResult = defaultResult;
    }

    /// <inheritdoc />
    public ValueTask<SipDialPlanResult> ProcessAsync(
        SipInviteContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ReadOnlySpan<byte> user = GetRequestUriUser(context.Request.RequestUri);
        foreach (SipDialPlanRule rule in _rules)
        {
            if (user.StartsWith(rule.Prefix))
            {
                return ValueTask.FromResult(rule.Result);
            }
        }

        return ValueTask.FromResult(_defaultResult);
    }

    private static ReadOnlySpan<byte> GetRequestUriUser(ReadOnlySpan<byte> uri)
    {
        int colon = uri.IndexOf((byte)':');
        if (colon < 0 || colon == uri.Length - 1)
        {
            return [];
        }

        ReadOnlySpan<byte> scheme = uri[..colon];
        ReadOnlySpan<byte> remainder = uri[(colon + 1)..];
        int parameters = remainder.IndexOfAny((byte)';', (byte)'?');
        ReadOnlySpan<byte> address = parameters < 0 ? remainder : remainder[..parameters];
        if (Ascii.EqualsIgnoreCase(scheme, "tel"u8))
        {
            return address;
        }

        if (!Ascii.EqualsIgnoreCase(scheme, "sip"u8) &&
            !Ascii.EqualsIgnoreCase(scheme, "sips"u8))
        {
            return [];
        }

        int at = address.IndexOf((byte)'@');
        return at <= 0 ? [] : address[..at];
    }
}

/// <summary>Validates INVITE requests and dispatches them to a dialplan processor.</summary>
public sealed class SipInviteRequestHandler : ISipRequestHandler
{
    private readonly ISipDialPlanProcessor _dialPlan;

    /// <summary>Initializes an INVITE handler with the supplied dialplan.</summary>
    public SipInviteRequestHandler(ISipDialPlanProcessor dialPlan)
    {
        ArgumentNullException.ThrowIfNull(dialPlan);
        _dialPlan = dialPlan;
    }

    /// <inheritdoc />
    public async ValueTask HandleAsync(
        SipRequestContext context,
        CancellationToken cancellationToken)
    {
        if (!Ascii.EqualsIgnoreCase(context.Message.Method, "INVITE"u8))
        {
            WriteResponse(context, context.Message, 501, "Not Implemented"u8);
            return;
        }

        int validationStatus = Validate(context.Message);
        if (validationStatus != 0)
        {
            WriteResponse(
                context,
                context.Message,
                validationStatus,
                validationStatus == 483 ? "Too Many Hops"u8 : "Bad Request"u8);
            return;
        }

        SipDialPlanResult result = await _dialPlan.ProcessAsync(
            new SipInviteContext(context),
            cancellationToken).ConfigureAwait(false);
        SipMessageView request = context.Message;
        if (!context.Response.WriteInviteResponse(request, result))
        {
            WriteResponse(context, request, 500, "Server Internal Error"u8);
        }
    }

    private static int Validate(SipMessageView request)
    {
        int cseqCount = 0;
        int contactCount = 0;
        int maxForwardsCount = 0;
        int viaCount = 0;
        int fromCount = 0;
        int toCount = 0;
        int callIdCount = 0;
        SipHeaderEnumerator headers = request.GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (Ascii.EqualsIgnoreCase(header.Name, "CSeq"u8))
            {
                if (++cseqCount > 1 || !IsInviteCSeq(header.Value))
                {
                    return 400;
                }
            }
            else if (Ascii.EqualsIgnoreCase(header.Name, "Contact"u8) ||
                Ascii.EqualsIgnoreCase(header.Name, "m"u8))
            {
                if (++contactCount > 1 || header.Value.IsEmpty)
                {
                    return 400;
                }
            }
            else if (Ascii.EqualsIgnoreCase(header.Name, "Max-Forwards"u8))
            {
                if (++maxForwardsCount > 1 ||
                    !TryParseNonNegativeInteger(header.Value, out int maxForwards))
                {
                    return 400;
                }

                if (maxForwards == 0)
                {
                    return 483;
                }
            }
            else if (Ascii.EqualsIgnoreCase(header.Name, "Via"u8) ||
                Ascii.EqualsIgnoreCase(header.Name, "v"u8))
            {
                viaCount++;
            }
            else if (Ascii.EqualsIgnoreCase(header.Name, "From"u8) ||
                Ascii.EqualsIgnoreCase(header.Name, "f"u8))
            {
                fromCount++;
            }
            else if (Ascii.EqualsIgnoreCase(header.Name, "To"u8) ||
                Ascii.EqualsIgnoreCase(header.Name, "t"u8))
            {
                toCount++;
            }
            else if (Ascii.EqualsIgnoreCase(header.Name, "Call-ID"u8) ||
                Ascii.EqualsIgnoreCase(header.Name, "i"u8))
            {
                callIdCount++;
            }
        }

        return cseqCount == 1 &&
            contactCount == 1 &&
            viaCount > 0 &&
            fromCount == 1 &&
            toCount == 1 &&
            callIdCount == 1
            ? 0
            : 400;
    }

    private static bool IsInviteCSeq(ReadOnlySpan<byte> value)
    {
        value = Ascii.TrimOptionalWhitespace(value);
        int separator = value.IndexOfAny((byte)' ', (byte)'\t');
        return separator > 0 &&
            TryParseNonNegativeInteger(value[..separator], out _) &&
            Ascii.EqualsIgnoreCase(
                Ascii.TrimOptionalWhitespace(value[separator..]),
                "INVITE"u8);
    }

    private static bool TryParseNonNegativeInteger(
        ReadOnlySpan<byte> value,
        out int result)
    {
        value = Ascii.TrimOptionalWhitespace(value);
        if (value.IsEmpty)
        {
            result = 0;
            return false;
        }

        int parsed = 0;
        foreach (byte digit in value)
        {
            if (digit is < (byte)'0' or > (byte)'9' ||
                parsed > (int.MaxValue - (digit - '0')) / 10)
            {
                result = 0;
                return false;
            }

            parsed = (parsed * 10) + digit - '0';
        }

        result = parsed;
        return true;
    }

    private static void WriteResponse(
        SipRequestContext context,
        SipMessageView request,
        int statusCode,
        ReadOnlySpan<byte> reasonPhrase)
    {
        if (!context.Response.WriteResponse(statusCode, reasonPhrase, request))
        {
            context.Response.WriteError(400);
        }
    }
}

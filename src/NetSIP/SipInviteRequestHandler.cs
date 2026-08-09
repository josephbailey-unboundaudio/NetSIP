using System.Net;
using System.Text;

namespace NetSIP;

/// <summary>
/// Exposes borrowed INVITE data that remains valid only until the dialplan call completes.
/// </summary>
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

    /// <summary>Gets the final SIP status code in the range 200 through 699.</summary>
    public int StatusCode { get; }

    /// <summary>Gets the owned reason phrase bytes.</summary>
    public ReadOnlyMemory<byte> ReasonPhrase { get; }

    /// <summary>Gets the owned Contact header value for successful or redirect responses.</summary>
    public ReadOnlyMemory<byte> Contact { get; }

    /// <summary>Gets the optional owned response body.</summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>Gets the owned Content-Type value required by a non-empty body.</summary>
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
    /// <param name="contact">The complete Contact header value.</param>
    /// <param name="body">An optional response body, commonly SDP.</param>
    /// <param name="contentType">The body media type; required when <paramref name="body"/> is non-empty.</param>
    /// <returns>An owned 200 OK result.</returns>
    public static SipDialPlanResult Answer(
        ReadOnlyMemory<byte> contact,
        ReadOnlyMemory<byte> body = default,
        ReadOnlyMemory<byte> contentType = default)
    {
        return new(200, "OK"u8.ToArray(), contact, body, contentType);
    }

    /// <summary>Creates a redirect response with a Contact.</summary>
    /// <param name="contact">The complete Contact header value for the redirect target.</param>
    /// <param name="statusCode">A final 3xx status code.</param>
    /// <param name="reasonPhrase">An optional owned reason phrase.</param>
    /// <returns>An owned redirect result.</returns>
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
    /// <param name="statusCode">A final status code from 400 through 699.</param>
    /// <param name="reasonPhrase">The owned reason phrase.</param>
    /// <returns>An owned rejection result.</returns>
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
    /// <param name="prefix">
    /// A visible ASCII prefix. An empty prefix is a catch-all rule.
    /// </param>
    /// <param name="result">The final response selected by a match.</param>
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
    /// <param name="rules">The rules to copy and order by descending prefix length.</param>
    /// <param name="defaultResult">The result used when no rule matches.</param>
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
        ReadOnlySpan<byte> user = SipUri.GetUser(context.Request.RequestUri);
        foreach (SipDialPlanRule rule in _rules)
        {
            if (user.StartsWith(rule.Prefix))
            {
                return ValueTask.FromResult(rule.Result);
            }
        }

        return ValueTask.FromResult(_defaultResult);
    }

}

internal static class SipUri
{
    /// <summary>
    /// Returns the borrowed user component for SIP/SIPS URIs or the subscriber
    /// component for tel URIs. Host-only and unsupported URIs return an empty span.
    /// </summary>
    public static ReadOnlySpan<byte> GetUser(ReadOnlySpan<byte> uri)
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
        if (AsciiUtilities.EqualsIgnoreCase(scheme, "tel"u8))
        {
            return address;
        }

        if (!AsciiUtilities.EqualsIgnoreCase(scheme, "sip"u8) &&
            !AsciiUtilities.EqualsIgnoreCase(scheme, "sips"u8))
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
    /// <param name="dialPlan">The processor invoked after structural request validation.</param>
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
        if (!AsciiUtilities.EqualsIgnoreCase(context.Message.Method, "INVITE"u8))
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
            if (AsciiUtilities.EqualsIgnoreCase(header.Name, "CSeq"u8))
            {
                if (++cseqCount > 1 || !IsInviteCSeq(header.Value))
                {
                    return 400;
                }
            }
            else if (AsciiUtilities.EqualsIgnoreCase(header.Name, "Contact"u8) ||
                AsciiUtilities.EqualsIgnoreCase(header.Name, "m"u8))
            {
                if (++contactCount > 1 || header.Value.IsEmpty)
                {
                    return 400;
                }
            }
            else if (AsciiUtilities.EqualsIgnoreCase(header.Name, "Max-Forwards"u8))
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
            else if (AsciiUtilities.EqualsIgnoreCase(header.Name, "Via"u8) ||
                AsciiUtilities.EqualsIgnoreCase(header.Name, "v"u8))
            {
                viaCount++;
            }
            else if (AsciiUtilities.EqualsIgnoreCase(header.Name, "From"u8) ||
                AsciiUtilities.EqualsIgnoreCase(header.Name, "f"u8))
            {
                fromCount++;
            }
            else if (AsciiUtilities.EqualsIgnoreCase(header.Name, "To"u8) ||
                AsciiUtilities.EqualsIgnoreCase(header.Name, "t"u8))
            {
                toCount++;
            }
            else if (AsciiUtilities.EqualsIgnoreCase(header.Name, "Call-ID"u8) ||
                AsciiUtilities.EqualsIgnoreCase(header.Name, "i"u8))
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
        value = AsciiUtilities.TrimOptionalWhitespace(value);
        int separator = value.IndexOfAny((byte)' ', (byte)'\t');
        return separator > 0 &&
            TryParseNonNegativeInteger(value[..separator], out _) &&
            AsciiUtilities.EqualsIgnoreCase(
                AsciiUtilities.TrimOptionalWhitespace(value[separator..]),
                "INVITE"u8);
    }

    private static bool TryParseNonNegativeInteger(
        ReadOnlySpan<byte> value,
        out int result)
    {
        value = AsciiUtilities.TrimOptionalWhitespace(value);
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

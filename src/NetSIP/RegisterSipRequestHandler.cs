using System.Text;

namespace NetSIP;

/// <summary>Limits and expiration policy for the bounded in-memory REGISTER handler.</summary>
public sealed class SipRegisterHandlerOptions
{
    /// <summary>
    /// Gets or initializes the default expiration time in seconds for registrations.
    /// </summary>
    public int DefaultExpirationSeconds { get; init; } = 180;

    /// <summary>
    /// Gets or initializes the minimum allowed expiration time in seconds.
    /// </summary>
    public int MinimumExpirationSeconds { get; init; } = 90;

    /// <summary>
    /// Gets or initializes the maximum allowed expiration time in seconds.
    /// </summary>
    public int MaximumExpirationSeconds { get; init; } = 300;

    /// <summary>
    /// Gets or initializes the maximum number of addresses of record that can be stored.
    /// </summary>
    public int MaxAddressesOfRecord { get; init; } = 10_000;

    /// <summary>
    /// Gets or initializes the maximum number of bindings per address of record.
    /// </summary>
    public int MaxBindingsPerAddress { get; init; } = 32;

    /// <summary>
    /// Gets or initializes the maximum number of unique Call-IDs tracked per address.
    /// </summary>
    public int MaxCallIdsPerAddress { get; init; } = 64;

    /// <summary>
    /// Gets or initializes the maximum size of one complete Contact field value.
    /// </summary>
    public int MaxContactBytes { get; init; } = 2048;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of an address of record.
    /// </summary>
    public int MaxAddressOfRecordBytes { get; init; } = 512;

    /// <summary>
    /// Gets or initializes the maximum size in bytes of a Call-ID.
    /// </summary>
    public int MaxCallIdBytes { get; init; } = 256;

    /// <summary>
    /// Gets or initializes the maximum estimated memory attributed to registrar state.
    /// </summary>
    public long MaxStoredBytes { get; init; } = 16 * 1024 * 1024;

    /// <summary>
    /// Validates that all options have valid values and consistent expiration policy.
    /// </summary>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(DefaultExpirationSeconds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MinimumExpirationSeconds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumExpirationSeconds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxAddressesOfRecord);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxBindingsPerAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxCallIdsPerAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxContactBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxAddressOfRecordBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxCallIdBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxStoredBytes);

        if (MinimumExpirationSeconds > DefaultExpirationSeconds ||
            DefaultExpirationSeconds > MaximumExpirationSeconds)
        {
            throw new ArgumentException(
                "Expiration policy must satisfy minimum <= default <= maximum.");
        }
    }
}

/// <summary>
/// Handles REGISTER using a bounded, process-local location store. Bindings are
/// removed on expiration and are not durable across process restarts.
/// </summary>
public sealed class RegisterSipRequestHandler : ISipRequestHandler
{
    /// <summary>
    /// Serializes transactional updates to all registrar state and accounting.
    /// </summary>
    private readonly Lock _gate = new();

    /// <summary>
    /// Registrar state keyed by canonical address of record.
    /// </summary>
    private readonly Dictionary<string, AddressBindings> _addresses =
        [with(StringComparer.Ordinal)];

    /// <summary>
    /// Validated handler policy and resource limits.
    /// </summary>
    private readonly SipRegisterHandlerOptions _options;

    /// <summary>
    /// Clock used for binding and replay-order expiration.
    /// </summary>
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Estimated total bytes currently stored.
    /// </summary>
    private long _storedBytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="RegisterSipRequestHandler"/> class.
    /// </summary>
    /// <param name="options">The handler options, or null to use defaults.</param>
    /// <param name="timeProvider">The time provider, or null to use the system time.</param>
    public RegisterSipRequestHandler(
        SipRegisterHandlerOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _options = options ?? new SipRegisterHandlerOptions();
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Handles REGISTER synchronously and rejects other methods with 501.
    /// </summary>
    /// <param name="context">The request context.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>A completed operation after the response has been buffered.</returns>
    public ValueTask HandleAsync(SipRequestContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Handle(context, context.Message);
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Parses, applies, and serializes one REGISTER transaction.
    /// </summary>
    internal void Handle(SipRequestContext context, SipMessageView message)
    {
        if (!Ascii.EqualsIgnoreCase(message.Method, "REGISTER"u8))
        {
            WriteFailure(context, message, 501, "Not Implemented"u8);
            return;
        }

        ParseResult parseResult = TryParseRequest(message, out RegisterRequest request);
        if (parseResult == ParseResult.Malformed)
        {
            WriteFailure(context, message, 400, "Bad Request"u8);
            return;
        }

        if (parseResult == ParseResult.IntervalTooBrief)
        {
            if (!context.Response.WriteRegisterIntervalTooBrief(
                    message,
                    _options.MinimumExpirationSeconds))
            {
                context.Response.WriteError(400);
            }

            return;
        }

        ProcessResult processResult = Apply(request, out SipRegistrationBinding[] bindings);
        if (processResult == ProcessResult.StaleSequence)
        {
            WriteFailure(context, message, 500, "Server Internal Error"u8);
            return;
        }

        if (processResult == ProcessResult.CapacityExceeded)
        {
            WriteFailure(context, message, 503, "Service Unavailable"u8);
            return;
        }

        if (!context.Response.WriteRegisterOk(message, bindings))
        {
            context.Response.WriteError(400);
        }
    }

    /// <summary>
    /// Applies a parsed REGISTER request to the in-memory registration state.
    /// Handles expiration cleanup, CSeq validation, binding updates, and capacity checks.
    /// </summary>
    /// <param name="request">The parsed registration request.</param>
    /// <param name="bindings">Returns the current bindings after the update.</param>
    /// <returns>The result of processing the registration request.</returns>
    private ProcessResult Apply(
        RegisterRequest request,
        out SipRegistrationBinding[] bindings)
    {
        long now = _timeProvider.GetUtcNow().UtcTicks;
        lock (_gate)
        {
            _ = _addresses.TryGetValue(request.AddressOfRecord, out AddressBindings? address);
            if (address is not null)
            {
                long beforeCleanup = EstimateAddressBytes(request.AddressOfRecord, address);
                RemoveExpired(address, now);
                if (address.Bindings.Count == 0 && address.Sequences.Count == 0)
                {
                    _ = _addresses.Remove(request.AddressOfRecord);
                    _storedBytes -= beforeCleanup;
                    address = null;
                }
                else
                {
                    _storedBytes +=
                        EstimateAddressBytes(request.AddressOfRecord, address) -
                        beforeCleanup;
                }
            }

            // Equal CSeq is idempotent; a lower value is stale for this Call-ID.
            if (address is not null &&
                address.Sequences.TryGetValue(
                    request.CallId,
                    out StoredSequence? priorSequence))
            {
                if (request.CSeq < priorSequence.CSeq)
                {
                    bindings = [];
                    return ProcessResult.StaleSequence;
                }

                if (request.CSeq == priorSequence.CSeq)
                {
                    bindings = Snapshot(address, now);
                    return ProcessResult.Success;
                }
            }
            else if (address is not null &&
                address.Sequences.Count >= _options.MaxCallIdsPerAddress)
            {
                bindings = [];
                return ProcessResult.CapacityExceeded;
            }

            // Mutate clones so a capacity failure cannot partially update live state.
            Dictionary<string, StoredBinding> updatedBindings = address is null
                ? [with(StringComparer.Ordinal)]
                : new Dictionary<string, StoredBinding>(
                    address.Bindings,
                    StringComparer.Ordinal);
            Dictionary<string, StoredSequence> updatedSequences = address is null
                ? [with(StringComparer.Ordinal)]
                : new Dictionary<string, StoredSequence>(
                    address.Sequences,
                    StringComparer.Ordinal);

            if (request.Wildcard)
            {
                updatedBindings.Clear();
            }
            else if (request.Changes is { Count: > 0 } changes)
            {
                foreach (RegistrationChange change in changes)
                {
                    if (change.ExpirationSeconds == 0)
                    {
                        _ = updatedBindings.Remove(change.Key);
                        continue;
                    }

                    long expirationTicks = checked(
                        now + (change.ExpirationSeconds * TimeSpan.TicksPerSecond));
                    updatedBindings[change.Key] =
                        new StoredBinding(change.Contact, expirationTicks);
                }
            }

            // Do not create state for a no-op query or removal of an unknown address.
            bool createsState = updatedBindings.Count > 0 || address is not null;
            if (!createsState)
            {
                bindings = [];
                return ProcessResult.Success;
            }

            // Retain ordering state long enough to cover the maximum binding lifetime.
            updatedSequences[request.CallId] = new StoredSequence(
                request.CSeq,
                checked(now + (_options.MaximumExpirationSeconds * TimeSpan.TicksPerSecond)));
            if (updatedBindings.Count > _options.MaxBindingsPerAddress ||
                updatedSequences.Count > _options.MaxCallIdsPerAddress)
            {
                bindings = [];
                return ProcessResult.CapacityExceeded;
            }

            if (address is null && _addresses.Count >= _options.MaxAddressesOfRecord)
            {
                ReclaimExpiredAddresses(now);
                if (_addresses.Count >= _options.MaxAddressesOfRecord)
                {
                    bindings = [];
                    return ProcessResult.CapacityExceeded;
                }
            }

            AddressBindings updatedAddress = new()
            {
                Bindings = updatedBindings,
                Sequences = updatedSequences
            };
            long priorBytes = address is null
                ? 0
                : EstimateAddressBytes(request.AddressOfRecord, address);
            long updatedBytes = EstimateAddressBytes(
                request.AddressOfRecord,
                updatedAddress);
            long projectedBytes = _storedBytes - priorBytes + updatedBytes;
            if (projectedBytes > _options.MaxStoredBytes)
            {
                ReclaimExpiredAddresses(now);
                projectedBytes = _storedBytes - priorBytes + updatedBytes;
                if (projectedBytes > _options.MaxStoredBytes)
                {
                    bindings = [];
                    return ProcessResult.CapacityExceeded;
                }
            }

            // Publish both dictionaries and accounting as one locked transaction.
            _addresses[request.AddressOfRecord] = updatedAddress;
            _storedBytes = projectedBytes;
            bindings = Snapshot(updatedAddress, now);
            return ProcessResult.Success;
        }
    }

    /// <summary>
    /// Parses a REGISTER request message and extracts registration details.
    /// Validates message structure and enforces required header constraints.
    /// </summary>
    /// <param name="message">The SIP message to parse.</param>
    /// <param name="request">Returns the parsed registration request on success.</param>
    /// <returns>The parse result indicating success or the reason for failure.</returns>
    private ParseResult TryParseRequest(
        SipMessageView message,
        out RegisterRequest request)
    {
        string? addressOfRecord = null;
        string? callId = null;
        int cseqCount = 0;
        int cseq = 0;
        int viaCount = 0;
        int fromCount = 0;
        int toCount = 0;
        int callIdCount = 0;
        int expiresCount = 0;
        int globalExpiration = _options.DefaultExpirationSeconds;
        List<RegistrationChange>? changes = null;
        bool wildcard = false;
        int contactCount = 0;

        SipHeaderEnumerator headers = message.GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (IsVia(header.Name))
            {
                viaCount++;
            }
            else if (IsFrom(header.Name))
            {
                fromCount++;
            }
            else if (IsTo(header.Name))
            {
                if (++toCount > 1 ||
                    !TryExtractSipUri(
                        header.Value,
                        SipUriContext.To,
                        out ReadOnlySpan<byte> uri) ||
                    uri.Length > _options.MaxAddressOfRecordBytes ||
                    !TryCanonicalizeSipUri(uri, out addressOfRecord))
                {
                    request = default;
                    return ParseResult.Malformed;
                }
            }
            else if (IsCSeq(header.Name))
            {
                if (++cseqCount > 1 ||
                    !TryParseRegisterCSeq(header.Value, out cseq))
                {
                    request = default;
                    return ParseResult.Malformed;
                }
            }
            else if (IsCallId(header.Name))
            {
                ReadOnlySpan<byte> value = header.Value;
                if (++callIdCount > 1 ||
                    value.IsEmpty ||
                    value.Length > _options.MaxCallIdBytes)
                {
                    request = default;
                    return ParseResult.Malformed;
                }

                callId = Encoding.ASCII.GetString(value);
            }
            else if (IsExpires(header.Name))
            {
                if (++expiresCount > 1 ||
                    !TryParseNonNegativeInteger(header.Value, out globalExpiration))
                {
                    request = default;
                    return ParseResult.Malformed;
                }
            }
        }

        if (addressOfRecord is null ||
            callId is null ||
            viaCount == 0 ||
            fromCount != 1 ||
            toCount != 1 ||
            callIdCount != 1 ||
            cseqCount != 1)
        {
            request = default;
            return ParseResult.Malformed;
        }

        headers = message.GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (!IsContact(header.Name))
            {
                continue;
            }

            if (!TryParseContactHeader(
                    header.Value,
                    globalExpiration,
                    ref changes,
                    ref contactCount,
                    ref wildcard,
                    out ParseResult contactResult))
            {
                request = default;
                return contactResult;
            }
        }

        if (wildcard &&
            (contactCount != 1 || expiresCount != 1 || globalExpiration != 0))
        {
            request = default;
            return ParseResult.Malformed;
        }

        request = new RegisterRequest(
            addressOfRecord,
            callId,
            cseq,
            changes,
            wildcard);
        return ParseResult.Success;
    }

    private bool TryParseContactHeader(
        ReadOnlySpan<byte> value,
        int globalExpiration,
        ref List<RegistrationChange>? changes,
        ref int contactCount,
        ref bool wildcard,
        out ParseResult result)
    {
        int itemStart = 0;
        bool quoted = false;
        bool escaped = false;
        int angleDepth = 0;

        for (int index = 0; index <= value.Length; index++)
        {
            bool atEnd = index == value.Length;
            byte current = atEnd ? (byte)0 : value[index];
            if (!atEnd)
            {
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
                    if (++angleDepth > 1)
                    {
                        result = ParseResult.Malformed;
                        return false;
                    }

                    continue;
                }

                if (current == (byte)'>')
                {
                    if (--angleDepth < 0)
                    {
                        result = ParseResult.Malformed;
                        return false;
                    }

                    continue;
                }
            }

            if (!atEnd && (current != (byte)',' || angleDepth != 0))
            {
                continue;
            }

            if (quoted || angleDepth != 0)
            {
                result = ParseResult.Malformed;
                return false;
            }

            ReadOnlySpan<byte> item = Ascii.TrimOptionalWhitespace(value[itemStart..index]);
            if (item.IsEmpty)
            {
                result = ParseResult.Malformed;
                return false;
            }

            contactCount++;
            if (item.SequenceEqual("*"u8))
            {
                wildcard = true;
            }
            else
            {
                if (wildcard)
                {
                    result = ParseResult.Malformed;
                    return false;
                }

                if (!TryParseContact(
                        item,
                        globalExpiration,
                        out RegistrationChange change,
                        out result))
                {
                    return false;
                }

                changes ??= [];
                changes.Add(change);
            }

            itemStart = index + 1;
        }

        result = ParseResult.Success;
        return !wildcard || contactCount == 1;
    }

    private bool TryParseContact(
        ReadOnlySpan<byte> item,
        int globalExpiration,
        out RegistrationChange change,
        out ParseResult result)
    {
        if (!TryExtractSipUri(
                item,
                SipUriContext.Contact,
                out ReadOnlySpan<byte> uri) ||
            !TryCanonicalizeSipUri(uri, out string key) ||
            !TryFindExpiresParameter(
                item,
                out int expiresParameterStart,
                out int expiresParameterEnd,
                out int? explicitExpiration))
        {
            change = default;
            result = ParseResult.Malformed;
            return false;
        }

        int expiration = Math.Min(
            explicitExpiration ?? globalExpiration,
            _options.MaximumExpirationSeconds);
        if (expiration > 0 && expiration < _options.MinimumExpirationSeconds)
        {
            change = default;
            result = ParseResult.IntervalTooBrief;
            return false;
        }

        byte[] contact;
        if (expiresParameterStart < 0)
        {
            contact = item.ToArray();
        }
        else
        {
            contact = new byte[item.Length - (expiresParameterEnd - expiresParameterStart)];
            item[..expiresParameterStart].CopyTo(contact);
            item[expiresParameterEnd..].CopyTo(contact.AsSpan(expiresParameterStart));
        }

        if (contact.Length > _options.MaxContactBytes)
        {
            change = default;
            result = ParseResult.Malformed;
            return false;
        }

        change = new RegistrationChange(
            key,
            contact,
            expiration);
        result = ParseResult.Success;
        return true;
    }

    private static bool TryFindExpiresParameter(
        ReadOnlySpan<byte> contact,
        out int parameterStart,
        out int parameterEnd,
        out int? expiration)
    {
        parameterStart = -1;
        parameterEnd = -1;
        expiration = null;
        bool quoted = false;
        bool escaped = false;
        int angleDepth = 0;

        for (int index = 0; index < contact.Length; index++)
        {
            byte current = contact[index];
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

            int nameStart = index + 1;
            while (nameStart < contact.Length && Ascii.IsOptionalWhitespace(contact[nameStart]))
            {
                nameStart++;
            }

            if (nameStart + 7 > contact.Length ||
                !Ascii.EqualsIgnoreCase(contact.Slice(nameStart, 7), "expires"u8))
            {
                continue;
            }

            int cursor = nameStart + 7;
            if (cursor < contact.Length &&
                !Ascii.IsOptionalWhitespace(contact[cursor]) &&
                contact[cursor] != (byte)'=')
            {
                continue;
            }

            while (cursor < contact.Length && Ascii.IsOptionalWhitespace(contact[cursor]))
            {
                cursor++;
            }

            if (cursor >= contact.Length || contact[cursor++] != (byte)'=')
            {
                return false;
            }

            while (cursor < contact.Length && Ascii.IsOptionalWhitespace(contact[cursor]))
            {
                cursor++;
            }

            int valueStart = cursor;
            while (cursor < contact.Length && contact[cursor] != (byte)';')
            {
                cursor++;
            }

            ReadOnlySpan<byte> value = Ascii.TrimOptionalWhitespace(contact[valueStart..cursor]);
            if (expiration.HasValue ||
                !TryParseNonNegativeInteger(value, out int parsed))
            {
                return false;
            }

            expiration = parsed;
            parameterStart = index;
            parameterEnd = cursor;
            index = cursor - 1;
        }

        return !quoted && angleDepth == 0;
    }

    private static bool TryExtractSipUri(
        ReadOnlySpan<byte> value,
        SipUriContext context,
        out ReadOnlySpan<byte> uri)
    {
        value = Ascii.TrimOptionalWhitespace(value);
        int open = FindOutsideQuotes(value, (byte)'<', 0);
        if (open >= 0)
        {
            int close = FindOutsideQuotes(value, (byte)'>', open + 1);
            if (close < 0)
            {
                uri = default;
                return false;
            }

            uri = Ascii.TrimOptionalWhitespace(
                value[(open + 1)..close]);
        }
        else
        {
            int parameter = FindHeaderParameterStart(value, context);
            uri = Ascii.TrimOptionalWhitespace(
                parameter < 0 ? value : value[..parameter]);
        }

        bool sip = uri.Length >= 4 &&
            Ascii.EqualsIgnoreCase(uri[..4], "sip:"u8);
        bool sips = uri.Length >= 5 &&
            Ascii.EqualsIgnoreCase(uri[..5], "sips:"u8);
        if (!sip && !sips)
        {
            return false;
        }

        int colon = uri.IndexOf((byte)':');
        if (colon < 0 || colon == uri.Length - 1)
        {
            return false;
        }

        foreach (byte current in uri)
        {
            if (current is <= 0x20 or >= 0x7f or
                (byte)'<' or (byte)'>' or (byte)',' or (byte)'"')
            {
                return false;
            }
        }

        ReadOnlySpan<byte> address = uri[(colon + 1)..];
        int headers = address.IndexOf((byte)'?');
        if (headers >= 0)
        {
            address = address[..headers];
        }

        int at = address.LastIndexOf((byte)'@');
        if (at == 0 || at == address.Length - 1)
        {
            return false;
        }

        ReadOnlySpan<byte> hostAndParameters = at < 0 ? address : address[(at + 1)..];
        int parameters = hostAndParameters.IndexOf((byte)';');
        ReadOnlySpan<byte> hostPort = parameters < 0
            ? hostAndParameters
            : hostAndParameters[..parameters];
        if (hostPort.IsEmpty)
        {
            return false;
        }

        if (hostPort[0] == (byte)'[')
        {
            int closeBracket = hostPort.IndexOf((byte)']');
            return closeBracket > 1 && (closeBracket == hostPort.Length - 1 ||
                (closeBracket + 1 < hostPort.Length &&
                hostPort[closeBracket + 1] == (byte)':' &&
                TryParsePort(hostPort[(closeBracket + 2)..])));
        }

        int portSeparator = hostPort.LastIndexOf((byte)':');
        ReadOnlySpan<byte> host = portSeparator < 0 ? hostPort : hostPort[..portSeparator];
        return !host.IsEmpty &&
            host.IndexOf((byte)':') < 0 &&
            (portSeparator < 0 || TryParsePort(hostPort[(portSeparator + 1)..]));
    }

    private static int FindHeaderParameterStart(
        ReadOnlySpan<byte> value,
        SipUriContext context)
    {
        for (int index = 0; index < value.Length; index++)
        {
            if (value[index] != (byte)';')
            {
                continue;
            }

            int nameStart = index + 1;
            int cursor = nameStart;
            while (cursor < value.Length &&
                value[cursor] is not (byte)'=' and not (byte)';')
            {
                cursor++;
            }

            ReadOnlySpan<byte> name = Ascii.TrimOptionalWhitespace(value[nameStart..cursor]);
            bool headerParameter = context switch
            {
                SipUriContext.Contact =>
                    Ascii.EqualsIgnoreCase(name, "expires"u8) ||
                    Ascii.EqualsIgnoreCase(name, "q"u8),
                SipUriContext.To => Ascii.EqualsIgnoreCase(name, "tag"u8),
                _ => false
            };
            if (headerParameter)
            {
                return index;
            }
        }

        return -1;
    }

    private static bool TryCanonicalizeSipUri(
        ReadOnlySpan<byte> uri,
        out string canonical)
    {
        string raw = Encoding.ASCII.GetString(uri);
        int colon = raw.IndexOf(':');
        int question = raw.IndexOf('?');
        int parameters = raw.IndexOf(';');
        int authorityEnd = raw.Length;
        if (parameters >= 0)
        {
            authorityEnd = parameters;
        }

        if (question >= 0 && question < authorityEnd)
        {
            authorityEnd = question;
        }

        if (colon <= 0 || colon + 1 >= authorityEnd)
        {
            canonical = string.Empty;
            return false;
        }

        string scheme = raw[..colon].ToLowerInvariant();
        string authority = raw[(colon + 1)..authorityEnd];
        int at = authority.LastIndexOf('@');
        string userInfo = string.Empty;
        string hostPort = authority;
        if (at >= 0)
        {
            if (!TryNormalizePercentEncoding(
                    authority[..at],
                    lowerCase: false,
                    out userInfo))
            {
                canonical = string.Empty;
                return false;
            }

            userInfo += "@";
            hostPort = authority[(at + 1)..];
        }

        string host;
        string port;
        if (hostPort.StartsWith('['))
        {
            int close = hostPort.IndexOf(']');
            if (close < 0)
            {
                canonical = string.Empty;
                return false;
            }

            host = hostPort[..(close + 1)].ToLowerInvariant();
            port = hostPort[(close + 1)..];
        }
        else
        {
            int portSeparator = hostPort.LastIndexOf(':');
            host = (portSeparator < 0 ? hostPort : hostPort[..portSeparator])
                .ToLowerInvariant();
            port = portSeparator < 0 ? string.Empty : hostPort[portSeparator..];
        }

        if ((scheme == "sip" && port == ":5060") ||
            (scheme == "sips" && port == ":5061"))
        {
            port = string.Empty;
        }

        List<string>? normalizedParameters = null;
        if (parameters >= 0)
        {
            int end = question < 0 ? raw.Length : question;
            string[] values = raw[(parameters + 1)..end].Split(
                ';',
                StringSplitOptions.RemoveEmptyEntries);
            normalizedParameters = [with(values.Length)];
            foreach (string value in values)
            {
                int equals = value.IndexOf('=');
                string name = (equals < 0 ? value : value[..equals])
                    .ToLowerInvariant();
                string parameterValue = equals < 0 ? string.Empty : value[(equals + 1)..];
                bool lowerValue =
                    name is "transport" or "user" or "method" or "maddr";
                if (!TryNormalizePercentEncoding(
                        parameterValue,
                        lowerValue,
                        out string normalizedValue))
                {
                    canonical = string.Empty;
                    return false;
                }

                normalizedParameters.Add(
                    equals < 0 ? name : $"{name}={normalizedValue}");
            }

            normalizedParameters.Sort(StringComparer.Ordinal);
        }

        List<string>? normalizedHeaders = null;
        if (question >= 0)
        {
            string[] values = raw[(question + 1)..].Split(
                '&',
                StringSplitOptions.RemoveEmptyEntries);
            normalizedHeaders = [with(values.Length)];
            foreach (string value in values)
            {
                int equals = value.IndexOf('=');
                string name = (equals < 0 ? value : value[..equals])
                    .ToLowerInvariant();
                string headerValue = equals < 0 ? string.Empty : value[(equals + 1)..];
                if (!TryNormalizePercentEncoding(
                        headerValue,
                        lowerCase: false,
                        out string normalizedValue))
                {
                    canonical = string.Empty;
                    return false;
                }

                normalizedHeaders.Add(
                    equals < 0 ? name : $"{name}={normalizedValue}");
            }

            normalizedHeaders.Sort(StringComparer.Ordinal);
        }

        StringBuilder builder = new(raw.Length);
        _ = builder.Append(scheme).Append(':').Append(userInfo).Append(host).Append(port);
        if (normalizedParameters is not null)
        {
            foreach (string value in normalizedParameters)
            {
                _ = builder.Append(';').Append(value);
            }
        }

        if (normalizedHeaders is not null)
        {
            _ = builder.Append('?');
            for (int index = 0; index < normalizedHeaders.Count; index++)
            {
                if (index > 0)
                {
                    _ = builder.Append('&');
                }

                _ = builder.Append(normalizedHeaders[index]);
            }
        }

        canonical = builder.ToString();
        return true;
    }

    private static bool TryNormalizePercentEncoding(
        string value,
        bool lowerCase,
        out string normalized)
    {
        StringBuilder builder = new(value.Length);
        for (int index = 0; index < value.Length; index++)
        {
            char current = value[index];
            if (current != '%')
            {
                _ = builder.Append(lowerCase ? char.ToLowerInvariant(current) : current);
                continue;
            }

            if (index + 2 >= value.Length ||
                !TryParseHex(value[index + 1], out int high) ||
                !TryParseHex(value[index + 2], out int low))
            {
                normalized = string.Empty;
                return false;
            }

            char decoded = (char)((high << 4) | low);
            _ = char.IsAsciiLetterOrDigit(decoded) ||
                decoded is '-' or '.' or '_' or '~'
                ? builder.Append(lowerCase ? char.ToLowerInvariant(decoded) : decoded)
                : builder.Append('%')
                    .Append(char.ToUpperInvariant(value[index + 1]))
                    .Append(char.ToUpperInvariant(value[index + 2]));

            index += 2;
        }

        normalized = builder.ToString();
        return true;
    }

    private static bool TryParseHex(char value, out int result)
    {
        if (value is >= '0' and <= '9')
        {
            result = value - '0';
            return true;
        }

        if (value is >= 'a' and <= 'f')
        {
            result = value - 'a' + 10;
            return true;
        }

        if (value is >= 'A' and <= 'F')
        {
            result = value - 'A' + 10;
            return true;
        }

        result = 0;
        return false;
    }

    private static int FindOutsideQuotes(
        ReadOnlySpan<byte> value,
        byte target,
        int start)
    {
        bool quoted = false;
        bool escaped = false;
        for (int index = 0; index < value.Length; index++)
        {
            byte current = value[index];
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
            }
            else if (index >= start && current == target)
            {
                return index;
            }
        }

        return -1;
    }

    private static bool TryParseRegisterCSeq(
        ReadOnlySpan<byte> value,
        out int sequence)
    {
        value = Ascii.TrimOptionalWhitespace(value);
        int separator = value.IndexOfAny((byte)' ', (byte)'\t');
        if (separator <= 0 ||
            !TryParseNonNegativeInteger(value[..separator], out sequence))
        {
            sequence = 0;
            return false;
        }

        return Ascii.EqualsIgnoreCase(
            Ascii.TrimOptionalWhitespace(value[separator..]),
            "REGISTER"u8);
    }

    private static bool TryParsePort(ReadOnlySpan<byte> value)
    {
        return TryParseNonNegativeInteger(value, out int port) &&
        port is > 0 and <= 65_535;
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

    private static bool IsContact(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "Contact"u8) ||
        Ascii.EqualsIgnoreCase(name, "m"u8);
    }

    private static bool IsExpires(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "Expires"u8);
    }

    private static bool IsVia(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "Via"u8) ||
        Ascii.EqualsIgnoreCase(name, "v"u8);
    }

    private static bool IsFrom(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "From"u8) ||
        Ascii.EqualsIgnoreCase(name, "f"u8);
    }

    private static bool IsTo(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "To"u8) ||
        Ascii.EqualsIgnoreCase(name, "t"u8);
    }

    private static bool IsCSeq(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "CSeq"u8);
    }

    private static bool IsCallId(ReadOnlySpan<byte> name)
    {
        return Ascii.EqualsIgnoreCase(name, "Call-ID"u8) ||
        Ascii.EqualsIgnoreCase(name, "i"u8);
    }

    /// <summary>
    /// Removes expired bindings and sequences from an address.
    /// </summary>
    private static void RemoveExpired(AddressBindings address, long now)
    {
        List<string>? expired = null;
        foreach ((string key, StoredBinding binding) in address.Bindings)
        {
            if (binding.ExpirationTicks <= now)
            {
                expired ??= [];
                expired.Add(key);
            }
        }

        if (expired is not null)
        {
            foreach (string key in expired)
            {
                _ = address.Bindings.Remove(key);
            }
        }

        expired = null;
        foreach ((string key, StoredSequence sequence) in address.Sequences)
        {
            if (sequence.RetainUntilTicks <= now)
            {
                expired ??= [];
                expired.Add(key);
            }
        }

        if (expired is not null)
        {
            foreach (string key in expired)
            {
                _ = address.Sequences.Remove(key);
            }
        }

    }

    /// <summary>
    /// Reclaims expired bindings across all stored addresses.
    /// Used when capacity limits are reached.
    /// </summary>
    private void ReclaimExpiredAddresses(long now)
    {
        List<string>? emptyAddresses = null;
        foreach ((string key, AddressBindings address) in _addresses)
        {
            long priorBytes = EstimateAddressBytes(key, address);
            RemoveExpired(address, now);
            if (address.Bindings.Count == 0 && address.Sequences.Count == 0)
            {
                emptyAddresses ??= [];
                emptyAddresses.Add(key);
                _storedBytes -= priorBytes;
            }
            else
            {
                _storedBytes += EstimateAddressBytes(key, address) - priorBytes;
            }
        }

        if (emptyAddresses is null)
        {
            return;
        }

        foreach (string key in emptyAddresses)
        {
            _ = _addresses.Remove(key);
        }
    }

    /// <summary>
    /// Conservatively estimates attributed managed memory for capacity enforcement.
    /// </summary>
    private static long EstimateAddressBytes(
        string addressOfRecord,
        AddressBindings address)
    {
        long total = EstimateStringBytes(addressOfRecord) + 128;
        foreach ((string key, StoredBinding binding) in address.Bindings)
        {
            total += EstimateStringBytes(key) + binding.Contact.Length + 96;
        }

        foreach (string callId in address.Sequences.Keys)
        {
            total += EstimateStringBytes(callId) + 64;
        }

        return total;
    }

    /// <summary>
    /// Estimates UTF-16 payload plus a fixed allowance for object/table overhead.
    /// </summary>
    private static long EstimateStringBytes(string value)
    {
        return checked((value.Length * sizeof(char)) + 64L);
    }

    /// <summary>
    /// Creates a snapshot of current bindings with remaining expiration times.
    /// </summary>
    private static SipRegistrationBinding[] Snapshot(
        AddressBindings address,
        long now)
    {
        if (address.Bindings.Count == 0)
        {
            return [];
        }

        SipRegistrationBinding[] bindings = new SipRegistrationBinding[address.Bindings.Count];
        int index = 0;
        foreach (StoredBinding stored in address.Bindings.Values)
        {
            long remainingTicks = Math.Max(0, stored.ExpirationTicks - now);
            // Never advertise zero seconds while a sub-second remainder is still live.
            int remainingSeconds = checked((int)Math.Min(
                int.MaxValue,
                (remainingTicks + TimeSpan.TicksPerSecond - 1) /
                TimeSpan.TicksPerSecond));
            bindings[index++] = new SipRegistrationBinding(
                stored.Contact,
                remainingSeconds);
        }

        return bindings;
    }

    /// <summary>
    /// Writes a failure response to the client.
    /// </summary>
    private static void WriteFailure(
        SipRequestContext context,
        SipMessageView message,
        int statusCode,
        ReadOnlySpan<byte> reason)
    {
        if (!context.Response.WriteResponse(statusCode, reason, message))
        {
            context.Response.WriteError(400);
        }
    }

    /// <summary>
    /// Stores registration state for a single address-of-record.
    /// </summary>
    private sealed class AddressBindings
    {
        /// <summary>
        /// Gets or sets active bindings keyed by canonical Contact identity.
        /// </summary>
        public Dictionary<string, StoredBinding> Bindings { get; set; } =
            [with(StringComparer.Ordinal)];

        /// <summary>
        /// Gets or sets replay-order state keyed by Call-ID.
        /// </summary>
        public Dictionary<string, StoredSequence> Sequences { get; set; } =
            [with(StringComparer.Ordinal)];
    }

    /// <summary>
    /// Owns a serialized Contact value and its absolute UTC expiration.
    /// </summary>
    private sealed record StoredBinding(byte[] Contact, long ExpirationTicks);

    /// <summary>
    /// Retains the highest accepted CSeq for a Call-ID until its safety window expires.
    /// </summary>
    private sealed record StoredSequence(int CSeq, long RetainUntilTicks);

    /// <summary>
    /// Describes one parsed Contact add, refresh, or removal.
    /// </summary>
    private readonly record struct RegistrationChange(
        string Key,
        byte[] Contact,
        int ExpirationSeconds);

    /// <summary>
    /// Owns the validated data needed after borrowed message parsing completes.
    /// </summary>
    private readonly record struct RegisterRequest(
        string AddressOfRecord,
        string CallId,
        int CSeq,
        List<RegistrationChange>? Changes,
        bool Wildcard);

    /// <summary>
    /// Selects URI rules that differ between To and Contact fields.
    /// </summary>
    private enum SipUriContext
    {
        /// <summary>An address-of-record URI from To.</summary>
        To,
        /// <summary>A binding URI from Contact.</summary>
        Contact
    }

    /// <summary>
    /// Result of parsing a REGISTER request.
    /// </summary>
    private enum ParseResult
    {
        /// <summary>Parsing succeeded.</summary>
        Success,
        /// <summary>Request is malformed.</summary>
        Malformed,
        /// <summary>Expiration interval is too brief.</summary>
        IntervalTooBrief
    }

    /// <summary>
    /// Result of processing a REGISTER request.
    /// </summary>
    private enum ProcessResult
    {
        /// <summary>Processing succeeded.</summary>
        Success,
        /// <summary>CSeq is older than a prior request.</summary>
        StaleSequence,
        /// <summary>Capacity limits were exceeded.</summary>
        CapacityExceeded
    }
}

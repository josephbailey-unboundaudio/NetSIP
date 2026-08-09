using System.Text;

namespace NetSIP;

/// <summary>Limits and expiration policy for the bounded in-memory REGISTER handler.</summary>
public sealed class SipRegisterHandlerOptions
{
    public int DefaultExpirationSeconds { get; init; } = 3600;

    public int MinimumExpirationSeconds { get; init; } = 60;

    public int MaximumExpirationSeconds { get; init; } = 86_400;

    public int MaxAddressesOfRecord { get; init; } = 10_000;

    public int MaxBindingsPerAddress { get; init; } = 32;

    public int MaxCallIdsPerAddress { get; init; } = 64;

    public int MaxContactBytes { get; init; } = 2048;

    public int MaxAddressOfRecordBytes { get; init; } = 512;

    public int MaxCallIdBytes { get; init; } = 256;

    public long MaxStoredBytes { get; init; } = 16 * 1024 * 1024;

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
    private readonly object _gate = new();
    private readonly Dictionary<string, AddressBindings> _addresses =
        new(StringComparer.Ordinal);
    private readonly SipRegisterHandlerOptions _options;
    private readonly TimeProvider _timeProvider;
    private long _storedBytes;

    public RegisterSipRequestHandler(
        SipRegisterHandlerOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _options = options ?? new SipRegisterHandlerOptions();
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ValueTask HandleAsync(SipRequestContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Handle(context, context.Message);
        return ValueTask.CompletedTask;
    }

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

    private ProcessResult Apply(
        RegisterRequest request,
        out SipRegistrationBinding[] bindings)
    {
        long now = _timeProvider.GetUtcNow().UtcTicks;
        lock (_gate)
        {
            _addresses.TryGetValue(request.AddressOfRecord, out AddressBindings? address);
            if (address is not null)
            {
                long beforeCleanup = EstimateAddressBytes(request.AddressOfRecord, address);
                RemoveExpired(address, now);
                if (address.Bindings.Count == 0 && address.Sequences.Count == 0)
                {
                    _addresses.Remove(request.AddressOfRecord);
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

            var updatedBindings = address is null
                ? new Dictionary<string, StoredBinding>(StringComparer.Ordinal)
                : new Dictionary<string, StoredBinding>(
                    address.Bindings,
                    StringComparer.Ordinal);
            var updatedSequences = address is null
                ? new Dictionary<string, StoredSequence>(StringComparer.Ordinal)
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
                        updatedBindings.Remove(change.Key);
                        continue;
                    }

                    long expirationTicks = checked(
                        now + (change.ExpirationSeconds * TimeSpan.TicksPerSecond));
                    updatedBindings[change.Key] =
                        new StoredBinding(change.Contact, expirationTicks);
                }
            }

            bool createsState = updatedBindings.Count > 0 || address is not null;
            if (!createsState)
            {
                bindings = [];
                return ProcessResult.Success;
            }

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

            var updatedAddress = new AddressBindings
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

            _addresses[request.AddressOfRecord] = updatedAddress;
            _storedBytes = projectedBytes;
            bindings = Snapshot(updatedAddress, now);
            return ProcessResult.Success;
        }
    }

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
            if (current is <= 0x20 or >= 0x7f ||
                current is (byte)'<' or (byte)'>' or (byte)',' or (byte)'"')
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
            if (closeBracket <= 1)
            {
                return false;
            }

            return closeBracket == hostPort.Length - 1 ||
                closeBracket + 1 < hostPort.Length &&
                hostPort[closeBracket + 1] == (byte)':' &&
                TryParsePort(hostPort[(closeBracket + 2)..]);
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
        string port = string.Empty;
        if (hostPort.StartsWith("[", StringComparison.Ordinal))
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
            normalizedParameters = new List<string>(values.Length);
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
            normalizedHeaders = new List<string>(values.Length);
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

        var builder = new StringBuilder(raw.Length);
        builder.Append(scheme).Append(':').Append(userInfo).Append(host).Append(port);
        if (normalizedParameters is not null)
        {
            foreach (string value in normalizedParameters)
            {
                builder.Append(';').Append(value);
            }
        }

        if (normalizedHeaders is not null)
        {
            builder.Append('?');
            for (int index = 0; index < normalizedHeaders.Count; index++)
            {
                if (index > 0)
                {
                    builder.Append('&');
                }

                builder.Append(normalizedHeaders[index]);
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
        var builder = new StringBuilder(value.Length);
        for (int index = 0; index < value.Length; index++)
        {
            char current = value[index];
            if (current != '%')
            {
                builder.Append(lowerCase ? char.ToLowerInvariant(current) : current);
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
            if (char.IsAsciiLetterOrDigit(decoded) ||
                decoded is '-' or '.' or '_' or '~')
            {
                builder.Append(lowerCase ? char.ToLowerInvariant(decoded) : decoded);
            }
            else
            {
                builder.Append('%')
                    .Append(char.ToUpperInvariant(value[index + 1]))
                    .Append(char.ToUpperInvariant(value[index + 2]));
            }

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

    private static bool TryParsePort(ReadOnlySpan<byte> value) =>
        TryParseNonNegativeInteger(value, out int port) &&
        port is > 0 and <= 65_535;

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

    private static bool IsContact(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "Contact"u8) ||
        Ascii.EqualsIgnoreCase(name, "m"u8);

    private static bool IsExpires(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "Expires"u8);

    private static bool IsVia(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "Via"u8) ||
        Ascii.EqualsIgnoreCase(name, "v"u8);

    private static bool IsFrom(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "From"u8) ||
        Ascii.EqualsIgnoreCase(name, "f"u8);

    private static bool IsTo(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "To"u8) ||
        Ascii.EqualsIgnoreCase(name, "t"u8);

    private static bool IsCSeq(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "CSeq"u8);

    private static bool IsCallId(ReadOnlySpan<byte> name) =>
        Ascii.EqualsIgnoreCase(name, "Call-ID"u8) ||
        Ascii.EqualsIgnoreCase(name, "i"u8);

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
                address.Bindings.Remove(key);
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
                address.Sequences.Remove(key);
            }
        }

    }

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
            _addresses.Remove(key);
        }
    }

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

    private static long EstimateStringBytes(string value) =>
        checked((value.Length * sizeof(char)) + 64L);

    private static SipRegistrationBinding[] Snapshot(
        AddressBindings address,
        long now)
    {
        if (address.Bindings.Count == 0)
        {
            return [];
        }

        var bindings = new SipRegistrationBinding[address.Bindings.Count];
        int index = 0;
        foreach (StoredBinding stored in address.Bindings.Values)
        {
            long remainingTicks = Math.Max(0, stored.ExpirationTicks - now);
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

    private sealed class AddressBindings
    {
        public Dictionary<string, StoredBinding> Bindings { get; set; } =
            new(StringComparer.Ordinal);

        public Dictionary<string, StoredSequence> Sequences { get; set; } =
            new(StringComparer.Ordinal);
    }

    private sealed record StoredBinding(byte[] Contact, long ExpirationTicks);

    private sealed record StoredSequence(int CSeq, long RetainUntilTicks);

    private readonly record struct RegistrationChange(
        string Key,
        byte[] Contact,
        int ExpirationSeconds);

    private readonly record struct RegisterRequest(
        string AddressOfRecord,
        string CallId,
        int CSeq,
        List<RegistrationChange>? Changes,
        bool Wildcard);

    private enum SipUriContext
    {
        To,
        Contact
    }

    private enum ParseResult
    {
        Success,
        Malformed,
        IntervalTooBrief
    }

    private enum ProcessResult
    {
        Success,
        StaleSequence,
        CapacityExceeded
    }
}

using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NetSIP;

/// <summary>Identifies the SIP methods protected by digest authentication.</summary>
[Flags]
public enum SipDigestProtectedMethods
{
    /// <summary>No methods are protected.</summary>
    None = 0,

    /// <summary>REGISTER requests are protected.</summary>
    Register = 1,

    /// <summary>INVITE requests are protected.</summary>
    Invite = 2
}

/// <summary>Identifies supported SIP Digest hash algorithms.</summary>
[Flags]
public enum SipDigestAlgorithms
{
    /// <summary>No algorithm is enabled.</summary>
    None = 0,

    /// <summary>SHA-256 is enabled and preferred.</summary>
    Sha256 = 1,

    /// <summary>Legacy MD5 is enabled for clients that cannot use SHA-256.</summary>
    Md5 = 2
}

/// <summary>Configures SIP Digest authentication.</summary>
public sealed class SipDigestAuthenticationOptions
{
    /// <summary>
    /// Gets the printable ASCII authentication realm advertised to clients.
    /// Quote and backslash are not permitted.
    /// </summary>
    public required string Realm { get; init; }

    /// <summary>Gets the nonce lifetime, from one second through 24 hours.</summary>
    public TimeSpan NonceLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets the maximum live nonce/user replay records. Authentication fails closed
    /// when this capacity is occupied until an entry expires.
    /// </summary>
    public int MaxTrackedAuthentications { get; init; } = 4096;

    /// <summary>Gets the maximum accepted Authorization field-value size in bytes.</summary>
    public int MaxAuthorizationHeaderBytes { get; init; } = 4096;

    /// <summary>Gets the maximum UTF-8 username size.</summary>
    public int MaxUserNameBytes { get; init; } = 256;

    /// <summary>
    /// Gets the advertised algorithms. SHA-256 is the secure default; MD5 is legacy-only.
    /// </summary>
    public SipDigestAlgorithms Algorithms { get; init; } = SipDigestAlgorithms.Sha256;

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Realm);
        if (!IsSafeRealm(Realm))
        {
            throw new ArgumentException(
                "The digest realm must contain printable ASCII characters other than quote and backslash.",
                nameof(Realm));
        }

        if (NonceLifetime < TimeSpan.FromSeconds(1) ||
            NonceLifetime > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(
                nameof(NonceLifetime),
                "NonceLifetime must be between one second and 24 hours.");
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxTrackedAuthentications);
        if (MaxAuthorizationHeaderBytes is < 256 or > 64 * 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxAuthorizationHeaderBytes),
                "MaxAuthorizationHeaderBytes must be between 256 and 65536.");
        }

        if (MaxUserNameBytes is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxUserNameBytes),
                "MaxUserNameBytes must be between 1 and 4096.");
        }

        if (Algorithms == SipDigestAlgorithms.None ||
            (Algorithms & ~(SipDigestAlgorithms.Sha256 | SipDigestAlgorithms.Md5)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(Algorithms));
        }
    }

    private static bool IsSafeRealm(string realm)
    {
        foreach (char value in realm)
        {
            if (value is < ' ' or > '~' or '"' or '\\')
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>A digest credential containing owned H(A1) values.</summary>
public readonly struct SipDigestCredential
{
    private readonly byte[]? _sha256Ha1;
    private readonly byte[]? _md5Ha1;

    private SipDigestCredential(byte[]? sha256Ha1, byte[]? md5Ha1)
    {
        _sha256Ha1 = sha256Ha1;
        _md5Ha1 = md5Ha1;
    }

    internal ReadOnlySpan<byte> Sha256Ha1 => _sha256Ha1;

    internal ReadOnlySpan<byte> Md5Ha1 => _md5Ha1;

    /// <summary>Creates SHA-256 and MD5 credentials from a username, realm, and password.</summary>
    /// <param name="userName">The exact username sent in the Authorization header.</param>
    /// <param name="realm">The realm configured by the authentication handler.</param>
    /// <param name="password">The user's plaintext password. It is not retained.</param>
    /// <returns>An owned credential containing both H(A1) variants.</returns>
    public static SipDigestCredential FromPassword(
        string userName,
        string realm,
        string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentNullException.ThrowIfNull(realm);
        ArgumentNullException.ThrowIfNull(password);

        int length = checked(
            Encoding.UTF8.GetByteCount(userName) +
            Encoding.UTF8.GetByteCount(realm) +
            Encoding.UTF8.GetByteCount(password) +
            2);
        byte[] rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            // H(A1) is retained; the pooled plaintext input is cleared before return.
            Span<byte> value = rented.AsSpan(0, length);
            int written = Encoding.UTF8.GetBytes(userName, value);
            value[written++] = (byte)':';
            written += Encoding.UTF8.GetBytes(realm, value[written..]);
            value[written++] = (byte)':';
            written += Encoding.UTF8.GetBytes(password, value[written..]);

            byte[] sha256 = new byte[32];
            byte[] md5 = new byte[16];
            SHA256.HashData(value[..written], sha256);
#pragma warning disable CA5351 // MD5 is required for explicitly enabled legacy SIP Digest interoperability.
            MD5.HashData(value[..written], md5);
#pragma warning restore CA5351
            return new SipDigestCredential(sha256, md5);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, length));
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>Creates a credential from a precomputed 32-byte SHA-256 H(A1) value.</summary>
    /// <param name="sha256Ha1">The binary SHA-256 digest, not its hexadecimal representation.</param>
    /// <returns>An owned SHA-256 credential.</returns>
    public static SipDigestCredential FromSha256Ha1(ReadOnlySpan<byte> sha256Ha1)
    {
        return sha256Ha1.Length == 32
            ? new SipDigestCredential(sha256Ha1.ToArray(), md5Ha1: null)
            : throw new ArgumentException(
                "A SHA-256 H(A1) value must contain 32 bytes.",
                nameof(sha256Ha1));
    }

    /// <summary>Creates a credential from a precomputed 16-byte MD5 H(A1) value.</summary>
    /// <param name="md5Ha1">The binary MD5 digest, not its hexadecimal representation.</param>
    /// <returns>An owned MD5 credential.</returns>
    public static SipDigestCredential FromMd5Ha1(ReadOnlySpan<byte> md5Ha1)
    {
        return md5Ha1.Length == 16
            ? new SipDigestCredential(sha256Ha1: null, md5Ha1.ToArray())
            : throw new ArgumentException(
                "An MD5 H(A1) value must contain 16 bytes.",
                nameof(md5Ha1));
    }
}

/// <summary>Resolves an owned digest credential for a username.</summary>
public interface ISipDigestCredentialProvider
{
    /// <summary>Looks up a credential without retaining request-owned data.</summary>
    /// <param name="userName">An owned username decoded as strict UTF-8.</param>
    /// <param name="cancellationToken">A token that cancels credential lookup.</param>
    /// <returns>The matching credential, or <see langword="null"/> for an unknown user.</returns>
    ValueTask<SipDigestCredential?> GetCredentialAsync(
        string userName,
        CancellationToken cancellationToken);
}

/// <summary>Stores pre-hashed digest credentials in process memory.</summary>
public sealed class InMemorySipDigestCredentialProvider : ISipDigestCredentialProvider
{
    private readonly Dictionary<string, SipDigestCredential> _credentials;

    /// <summary>Builds an immutable credential store without retaining plaintext passwords.</summary>
    /// <param name="realm">The realm used to calculate H(A1).</param>
    /// <param name="users">Username/password pairs to hash during construction.</param>
    public InMemorySipDigestCredentialProvider(
        string realm,
        IEnumerable<KeyValuePair<string, string>> users)
    {
        ArgumentNullException.ThrowIfNull(realm);
        ArgumentNullException.ThrowIfNull(users);
        _credentials = [];
        foreach (KeyValuePair<string, string> user in users)
        {
            ValidateUserName(user.Key);
            ArgumentNullException.ThrowIfNull(user.Value);
            _credentials.Add(
                user.Key,
                SipDigestCredential.FromPassword(user.Key, realm, user.Value));
        }
    }

    /// <inheritdoc />
    public ValueTask<SipDigestCredential?> GetCredentialAsync(
        string userName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            _credentials.TryGetValue(userName, out SipDigestCredential credential)
                ? (SipDigestCredential?)credential
                : null);
    }

    private static void ValidateUserName(string userName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        foreach (char value in userName)
        {
            if (char.IsControl(value) || value is '"' or '\\')
            {
                throw new ArgumentException(
                    "Digest usernames cannot contain controls, quote, or backslash.",
                    nameof(userName));
            }
        }
    }
}

/// <summary>
/// Authenticates selected SIP methods with Digest before delegating to another handler.
/// Authorization parsing and cryptographic work allocate outside the parser hot-path guarantee.
/// </summary>
public sealed class SipDigestAuthenticationHandler : ISipRequestHandler
{
    private const int NoncePayloadLength = 24;
    private const int NonceMacLength = 32;
    private const int NonceLength = (NoncePayloadLength + NonceMacLength) * 2;
    private const int DigestHashLength = 32;
    private static readonly UTF8Encoding s_strictUtf8 = new(false, true);

    private readonly ISipRequestHandler _inner;
    private readonly ISipDigestCredentialProvider _credentialProvider;
    private readonly SipDigestProtectedMethods _protectedMethods;
    private readonly TimeProvider _timeProvider;
    private readonly byte[] _realm;
    private readonly byte[] _nonceSecret;
    private readonly byte[] _unknownUserSha256Ha1;
    private readonly byte[] _unknownUserMd5Ha1;
    private readonly SipDigestAlgorithms _algorithms;
    private readonly int _nonceLifetimeSeconds;
    private readonly int _maxTrackedAuthentications;
    private readonly int _maxAuthorizationHeaderBytes;
    private readonly int _maxUserNameBytes;
    private readonly Lock _replayLock = new();
    private readonly Dictionary<ReplayKey, ReplayEntry> _replayEntries = [];

    /// <summary>Initializes a digest authentication gate.</summary>
    /// <param name="inner">The application handler invoked after authentication.</param>
    /// <param name="credentialProvider">The asynchronous credential source.</param>
    /// <param name="options">Digest limits, realm, nonce lifetime, and algorithms.</param>
    /// <param name="protectedMethods">The methods that require authentication.</param>
    /// <param name="timeProvider">An optional clock, primarily for deterministic testing.</param>
    public SipDigestAuthenticationHandler(
        ISipRequestHandler inner,
        ISipDigestCredentialProvider credentialProvider,
        SipDigestAuthenticationOptions options,
        SipDigestProtectedMethods protectedMethods =
            SipDigestProtectedMethods.Register | SipDigestProtectedMethods.Invite,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(credentialProvider);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (protectedMethods == SipDigestProtectedMethods.None ||
            (protectedMethods & ~(SipDigestProtectedMethods.Register | SipDigestProtectedMethods.Invite)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(protectedMethods));
        }

        _inner = inner;
        _credentialProvider = credentialProvider;
        _protectedMethods = protectedMethods;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _realm = Encoding.ASCII.GetBytes(options.Realm);
        _nonceSecret = RandomNumberGenerator.GetBytes(DigestHashLength);
        _unknownUserSha256Ha1 = RandomNumberGenerator.GetBytes(32);
        _unknownUserMd5Ha1 = RandomNumberGenerator.GetBytes(16);
        _algorithms = options.Algorithms;
        _nonceLifetimeSeconds = checked((int)Math.Ceiling(options.NonceLifetime.TotalSeconds));
        _maxTrackedAuthentications = options.MaxTrackedAuthentications;
        _maxAuthorizationHeaderBytes = options.MaxAuthorizationHeaderBytes;
        _maxUserNameBytes = options.MaxUserNameBytes;
    }

    /// <inheritdoc />
    public async ValueTask HandleAsync(
        SipRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!RequiresAuthentication(context.Message.Method))
        {
            await _inner.HandleAsync(context, cancellationToken).ConfigureAwait(false);
            return;
        }

        AuthenticationResult authentication =
            await AuthenticateAsync(context, cancellationToken).ConfigureAwait(false);
        if (authentication == AuthenticationResult.Authenticated)
        {
            await _inner.HandleAsync(context, cancellationToken).ConfigureAwait(false);
            return;
        }

        SipMessageView request = context.Message;
        byte[] nonce = CreateNonce();
        if (!context.Response.WriteDigestChallenge(
                request,
                _realm,
                nonce,
                _algorithms,
                authentication == AuthenticationResult.Stale))
        {
            context.Response.WriteError(400);
        }
    }

    private async ValueTask<AuthenticationResult> AuthenticateAsync(
        SipRequestContext context,
        CancellationToken cancellationToken)
    {
        SipMessageView initialRequest = context.Message;
        if (!TryGetDigestAuthorization(
                initialRequest,
                _maxAuthorizationHeaderBytes,
                out DigestAuthorizationView initialAuthorization) ||
            initialAuthorization.UserName.Length > _maxUserNameBytes)
        {
            return AuthenticationResult.Unauthorized;
        }

        string userName;
        byte[] userNameBytes = initialAuthorization.UserName.ToArray();
        try
        {
            userName = s_strictUtf8.GetString(userNameBytes);
        }
        catch (DecoderFallbackException)
        {
            return AuthenticationResult.Unauthorized;
        }

        SipDigestCredential? resolvedCredential =
            await _credentialProvider.GetCredentialAsync(userName, cancellationToken)
                .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        // The message is borrowed. Reacquire and reparse it after the asynchronous lookup.
        SipMessageView request = context.Message;
        if (!TryGetDigestAuthorization(
                request,
                _maxAuthorizationHeaderBytes,
                out DigestAuthorizationView authorization) ||
            !authorization.UserName.SequenceEqual(userNameBytes) ||
            !authorization.Realm.SequenceEqual(_realm) ||
            !Ascii.EqualsIgnoreCase(authorization.Qop, "auth"u8) ||
            !authorization.Uri.SequenceEqual(request.RequestUri) ||
            !TryParseNonceCount(authorization.NonceCount, out uint nonceCount) ||
            authorization.Cnonce.IsEmpty)
        {
            return AuthenticationResult.Unauthorized;
        }

        if (!TryGetAlgorithm(authorization.Algorithm, out DigestAlgorithm algorithm))
        {
            return AuthenticationResult.Unauthorized;
        }

        NonceStatus nonceStatus = ValidateNonce(
            authorization.Nonce,
            out long nonceExpiration,
            out NonceIdentity nonceIdentity);
        if (nonceStatus == NonceStatus.Expired)
        {
            return AuthenticationResult.Stale;
        }

        if (nonceStatus != NonceStatus.Valid)
        {
            return AuthenticationResult.Unauthorized;
        }

        int hashLength = GetHashLength(algorithm);
        Span<byte> actualResponseBuffer = stackalloc byte[DigestHashLength];
        Span<byte> actualResponse = actualResponseBuffer[..hashLength];
        if (!TryDecodeHex(authorization.Response, actualResponse, out int responseLength) ||
            responseLength != hashLength)
        {
            return AuthenticationResult.Unauthorized;
        }

        SipDigestCredential credential = resolvedCredential.GetValueOrDefault();
        ReadOnlySpan<byte> credentialHa1 = algorithm == DigestAlgorithm.Sha256
            ? credential.Sha256Ha1
            : credential.Md5Ha1;
        bool credentialIsValid = credentialHa1.Length == hashLength;
        // Unknown users perform the same digest work before rejection to reduce timing leakage.
        ReadOnlySpan<byte> ha1 = credentialIsValid
            ? credentialHa1
            : algorithm == DigestAlgorithm.Sha256
                ? _unknownUserSha256Ha1
                : _unknownUserMd5Ha1;
        Span<byte> expectedResponseBuffer = stackalloc byte[DigestHashLength];
        Span<byte> expectedResponse = expectedResponseBuffer[..hashLength];
        ComputeResponse(
            algorithm,
            ha1,
            request.Method,
            authorization.Uri,
            authorization.Nonce,
            authorization.NonceCount,
            authorization.Cnonce,
            authorization.Qop,
            expectedResponse);

        bool digestMatches = CryptographicOperations.FixedTimeEquals(
            expectedResponse,
            actualResponse);
        CryptographicOperations.ZeroMemory(expectedResponse);
        if (!credentialIsValid || !digestMatches)
        {
            return AuthenticationResult.Unauthorized;
        }

        ReplayKey replayKey = CreateReplayKey(nonceIdentity, authorization.UserName);
        return TryAcceptNonceCount(replayKey, nonceCount, nonceExpiration)
            ? AuthenticationResult.Authenticated
            : AuthenticationResult.Unauthorized;
    }

    private bool RequiresAuthentication(ReadOnlySpan<byte> method)
    {
        return
            ((_protectedMethods & SipDigestProtectedMethods.Invite) != 0 &&
                Ascii.EqualsIgnoreCase(method, "INVITE"u8)) ||
            ((_protectedMethods & SipDigestProtectedMethods.Register) != 0 &&
                Ascii.EqualsIgnoreCase(method, "REGISTER"u8));
    }

    private bool TryGetAlgorithm(
        ReadOnlySpan<byte> value,
        out DigestAlgorithm algorithm)
    {
        if (value.IsEmpty &&
            (_algorithms & SipDigestAlgorithms.Md5) != 0)
        {
            algorithm = DigestAlgorithm.Md5;
            return true;
        }

        if ((_algorithms & SipDigestAlgorithms.Sha256) != 0 &&
            Ascii.EqualsIgnoreCase(value, "SHA-256"u8))
        {
            algorithm = DigestAlgorithm.Sha256;
            return true;
        }

        if ((_algorithms & SipDigestAlgorithms.Md5) != 0 &&
            Ascii.EqualsIgnoreCase(value, "MD5"u8))
        {
            algorithm = DigestAlgorithm.Md5;
            return true;
        }

        algorithm = default;
        return false;
    }

    private byte[] CreateNonce()
    {
        // Nonce wire format is hex(timestamp || 128-bit random || HMAC-SHA256).
        Span<byte> payload = stackalloc byte[NoncePayloadLength];
        BinaryPrimitives.WriteInt64BigEndian(
            payload,
            _timeProvider.GetUtcNow().ToUnixTimeSeconds());
        RandomNumberGenerator.Fill(payload[sizeof(long)..]);

        Span<byte> mac = stackalloc byte[NonceMacLength];
        HMACSHA256.HashData(_nonceSecret, payload, mac);
        byte[] nonce = new byte[NonceLength];
        WriteLowerHex(payload, nonce);
        WriteLowerHex(mac, nonce.AsSpan(NoncePayloadLength * 2));
        return nonce;
    }

    private NonceStatus ValidateNonce(
        ReadOnlySpan<byte> nonce,
        out long expiration,
        out NonceIdentity identity)
    {
        Span<byte> decoded = stackalloc byte[NoncePayloadLength + NonceMacLength];
        expiration = 0;
        identity = default;
        if (nonce.Length != NonceLength ||
            !TryDecodeHex(nonce, decoded, out int decodedLength) ||
            decodedLength != decoded.Length)
        {
            return NonceStatus.Invalid;
        }

        ReadOnlySpan<byte> decodedPayload = decoded[..NoncePayloadLength];
        Span<byte> expectedMac = stackalloc byte[NonceMacLength];
        HMACSHA256.HashData(_nonceSecret, decodedPayload, expectedMac);
        if (!CryptographicOperations.FixedTimeEquals(
                expectedMac,
                decoded[NoncePayloadLength..]))
        {
            return NonceStatus.Invalid;
        }

        long issuedAt = BinaryPrimitives.ReadInt64BigEndian(decodedPayload);
        long now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (issuedAt > now)
        {
            return NonceStatus.Invalid;
        }

        expiration = issuedAt + _nonceLifetimeSeconds;
        identity = new NonceIdentity(
            BinaryPrimitives.ReadUInt64BigEndian(decodedPayload[sizeof(long)..]),
            BinaryPrimitives.ReadUInt64BigEndian(decodedPayload[(sizeof(long) * 2)..]));
        return now > expiration
            ? NonceStatus.Expired
            : NonceStatus.Valid;
    }

    private bool TryAcceptNonceCount(ReplayKey key, uint nonceCount, long expiration)
    {
        long now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        lock (_replayLock)
        {
            if (_replayEntries.TryGetValue(key, out ReplayEntry current))
            {
                if (current.Expiration >= now && nonceCount <= current.HighestNonceCount)
                {
                    return false;
                }

                _replayEntries[key] = new ReplayEntry(nonceCount, expiration);
                return true;
            }

            if (_replayEntries.Count >= _maxTrackedAuthentications)
            {
                // Never evict a live entry: doing so would make a captured nc replayable.
                if (!TryEvictExpiredReplayEntry(now))
                {
                    return false;
                }
            }

            _replayEntries.Add(
                key,
                new ReplayEntry(nonceCount, expiration));
            return true;
        }
    }

    private bool TryEvictExpiredReplayEntry(long now)
    {
        ReplayKey candidate = default;
        bool found = false;
        foreach (KeyValuePair<ReplayKey, ReplayEntry> entry in _replayEntries)
        {
            if (entry.Value.Expiration < now)
            {
                candidate = entry.Key;
                found = true;
                break;
            }
        }

        if (found)
        {
            _replayEntries.Remove(candidate);
        }

        return found;
    }

    private static ReplayKey CreateReplayKey(
        NonceIdentity nonce,
        ReadOnlySpan<byte> userName)
    {
        Span<byte> userHash = stackalloc byte[DigestHashLength];
        SHA256.HashData(userName, userHash);
        return new ReplayKey(
            nonce.High,
            nonce.Low,
            BinaryPrimitives.ReadUInt64BigEndian(userHash));
    }

    private static void ComputeResponse(
        DigestAlgorithm algorithm,
        ReadOnlySpan<byte> ha1,
        ReadOnlySpan<byte> method,
        ReadOnlySpan<byte> uri,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> nonceCount,
        ReadOnlySpan<byte> cnonce,
        ReadOnlySpan<byte> qop,
        Span<byte> destination)
    {
        int ha2InputLength = method.Length + uri.Length + 1;
        int hashLength = GetHashLength(algorithm);
        int responseInputLength =
            (hashLength * 2) +
            nonce.Length +
            nonceCount.Length +
            cnonce.Length +
            (hashLength * 2) +
            qop.Length +
            5;
        int rentedLength = Math.Max(ha2InputLength, responseInputLength);
        byte[] rented = ArrayPool<byte>.Shared.Rent(rentedLength);
        try
        {
            Span<byte> buffer = rented;
            int written = 0;
            method.CopyTo(buffer);
            written += method.Length;
            buffer[written++] = (byte)':';
            uri.CopyTo(buffer[written..]);
            written += uri.Length;
            Span<byte> ha2Buffer = stackalloc byte[DigestHashLength];
            Span<byte> ha2 = ha2Buffer[..hashLength];
            HashData(algorithm, buffer[..written], ha2);

            written = 0;
            WriteLowerHex(ha1, buffer);
            written += hashLength * 2;
            buffer[written++] = (byte)':';
            nonce.CopyTo(buffer[written..]);
            written += nonce.Length;
            buffer[written++] = (byte)':';
            nonceCount.CopyTo(buffer[written..]);
            written += nonceCount.Length;
            buffer[written++] = (byte)':';
            cnonce.CopyTo(buffer[written..]);
            written += cnonce.Length;
            buffer[written++] = (byte)':';
            qop.CopyTo(buffer[written..]);
            written += qop.Length;
            buffer[written++] = (byte)':';
            WriteLowerHex(ha2, buffer[written..]);
            written += hashLength * 2;
            HashData(algorithm, buffer[..written], destination);
            CryptographicOperations.ZeroMemory(ha2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, rentedLength));
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static int GetHashLength(DigestAlgorithm algorithm)
    {
        return algorithm == DigestAlgorithm.Sha256 ? 32 : 16;
    }

    private static void HashData(
        DigestAlgorithm algorithm,
        ReadOnlySpan<byte> value,
        Span<byte> destination)
    {
        if (algorithm == DigestAlgorithm.Sha256)
        {
            SHA256.HashData(value, destination);
            return;
        }

#pragma warning disable CA5351 // MD5 is required for explicitly enabled legacy SIP Digest interoperability.
        MD5.HashData(value, destination);
#pragma warning restore CA5351
    }

    private static bool TryGetDigestAuthorization(
        SipMessageView request,
        int maxHeaderBytes,
        out DigestAuthorizationView authorization)
    {
        authorization = default;
        int count = 0;
        SipHeaderEnumerator headers = request.GetHeaders();
        while (headers.MoveNext())
        {
            SipHeaderView header = headers.Current;
            if (!Ascii.EqualsIgnoreCase(header.Name, "Authorization"u8))
            {
                continue;
            }

            if (++count > 1 ||
                header.Value.Length > maxHeaderBytes ||
                !DigestAuthorizationView.TryParse(header.Value, out authorization))
            {
                authorization = default;
                return false;
            }
        }

        return count == 1;
    }

    private static bool TryParseNonceCount(ReadOnlySpan<byte> value, out uint result)
    {
        result = 0;
        if (value.Length != 8)
        {
            return false;
        }

        foreach (byte current in value)
        {
            int digit = FromHex(current);
            if (digit < 0)
            {
                result = 0;
                return false;
            }

            result = (result << 4) | (uint)digit;
        }

        return result != 0;
    }

    private static bool TryDecodeHex(
        ReadOnlySpan<byte> value,
        Span<byte> destination,
        out int written)
    {
        written = 0;
        if ((value.Length & 1) != 0 || destination.Length < value.Length / 2)
        {
            return false;
        }

        for (int index = 0; index < value.Length; index += 2)
        {
            int high = FromHex(value[index]);
            int low = FromHex(value[index + 1]);
            if (high < 0 || low < 0)
            {
                written = 0;
                return false;
            }

            destination[written++] = (byte)((high << 4) | low);
        }

        return true;
    }

    private static int FromHex(byte value)
    {
        return value switch
        {
            >= (byte)'0' and <= (byte)'9' => value - '0',
            >= (byte)'a' and <= (byte)'f' => value - 'a' + 10,
            >= (byte)'A' and <= (byte)'F' => value - 'A' + 10,
            _ => -1
        };
    }

    private static void WriteLowerHex(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        ReadOnlySpan<byte> alphabet = "0123456789abcdef"u8;
        for (int index = 0; index < value.Length; index++)
        {
            destination[index * 2] = alphabet[value[index] >> 4];
            destination[(index * 2) + 1] = alphabet[value[index] & 0x0f];
        }
    }

    private enum AuthenticationResult
    {
        Unauthorized,
        Stale,
        Authenticated
    }

    private enum NonceStatus
    {
        Invalid,
        Expired,
        Valid
    }

    private enum DigestAlgorithm
    {
        Sha256,
        Md5
    }

    private readonly record struct ReplayKey(ulong NonceHigh, ulong NonceLow, ulong User);

    private readonly record struct NonceIdentity(ulong High, ulong Low);

    private readonly record struct ReplayEntry(
        uint HighestNonceCount,
        long Expiration);

    private ref struct DigestAuthorizationView
    {
        public ReadOnlySpan<byte> UserName;
        public ReadOnlySpan<byte> Realm;
        public ReadOnlySpan<byte> Nonce;
        public ReadOnlySpan<byte> Uri;
        public ReadOnlySpan<byte> Response;
        public ReadOnlySpan<byte> Algorithm;
        public ReadOnlySpan<byte> Cnonce;
        public ReadOnlySpan<byte> NonceCount;
        public ReadOnlySpan<byte> Qop;

        public static bool TryParse(
            ReadOnlySpan<byte> value,
            out DigestAuthorizationView authorization)
        {
            authorization = default;
            value = Ascii.TrimOptionalWhitespace(value);
            const int schemeLength = 6;
            if (value.Length <= schemeLength ||
                !Ascii.EqualsIgnoreCase(value[..schemeLength], "Digest"u8) ||
                value[schemeLength] is not ((byte)' ' or (byte)'\t'))
            {
                return false;
            }

            value = value[schemeLength..];
            while (true)
            {
                value = Ascii.TrimOptionalWhitespace(value);
                if (value.IsEmpty)
                {
                    break;
                }

                int equals = value.IndexOf((byte)'=');
                if (equals <= 0)
                {
                    return false;
                }

                ReadOnlySpan<byte> name = Ascii.TrimOptionalWhitespace(value[..equals]);
                if (!IsToken(name))
                {
                    return false;
                }

                value = Ascii.TrimOptionalWhitespace(value[(equals + 1)..]);
                if (!TryReadParameterValue(value, out ReadOnlySpan<byte> parameter, out int consumed))
                {
                    return false;
                }

                if (!authorization.TrySet(name, parameter))
                {
                    return false;
                }

                value = Ascii.TrimOptionalWhitespace(value[consumed..]);
                if (value.IsEmpty)
                {
                    break;
                }

                if (value[0] != (byte)',')
                {
                    return false;
                }

                value = value[1..];
                if (Ascii.TrimOptionalWhitespace(value).IsEmpty)
                {
                    return false;
                }
            }

            return !authorization.UserName.IsEmpty &&
                !authorization.Realm.IsEmpty &&
                !authorization.Nonce.IsEmpty &&
                !authorization.Uri.IsEmpty &&
                !authorization.Response.IsEmpty &&
                !authorization.Cnonce.IsEmpty &&
                !authorization.NonceCount.IsEmpty &&
                !authorization.Qop.IsEmpty;
        }

        private bool TrySet(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
        {
            return Ascii.EqualsIgnoreCase(name, "username"u8)
                ? SetOnce(ref UserName, value)
                : Ascii.EqualsIgnoreCase(name, "realm"u8)
                    ? SetOnce(ref Realm, value)
                    : Ascii.EqualsIgnoreCase(name, "nonce"u8)
                        ? SetOnce(ref Nonce, value)
                        : Ascii.EqualsIgnoreCase(name, "uri"u8)
                            ? SetOnce(ref Uri, value)
                            : Ascii.EqualsIgnoreCase(name, "response"u8)
                                ? SetOnce(ref Response, value)
                                : Ascii.EqualsIgnoreCase(name, "algorithm"u8)
                                    ? SetOnce(ref Algorithm, value)
                                    : Ascii.EqualsIgnoreCase(name, "cnonce"u8)
                                        ? SetOnce(ref Cnonce, value)
                                        : Ascii.EqualsIgnoreCase(name, "nc"u8)
                                            ? SetOnce(ref NonceCount, value)
                                            : !Ascii.EqualsIgnoreCase(name, "qop"u8) ||
                                                SetOnce(ref Qop, value);
        }

        private static bool SetOnce(
            ref ReadOnlySpan<byte> destination,
            ReadOnlySpan<byte> value)
        {
            if (!destination.IsEmpty || value.IsEmpty)
            {
                return false;
            }

            destination = value;
            return true;
        }

        private static bool TryReadParameterValue(
            ReadOnlySpan<byte> value,
            out ReadOnlySpan<byte> parameter,
            out int consumed)
        {
            parameter = default;
            consumed = 0;
            if (value.IsEmpty)
            {
                return false;
            }

            if (value[0] == (byte)'"')
            {
                // Escaped quoted-pairs are intentionally rejected rather than normalized.
                for (int index = 1; index < value.Length; index++)
                {
                    byte current = value[index];
                    if (current == (byte)'"')
                    {
                        parameter = value[1..index];
                        consumed = index + 1;
                        return !parameter.IsEmpty;
                    }

                    if (current is (byte)'\\' or < 0x20 or 0x7f)
                    {
                        return false;
                    }
                }

                return false;
            }

            int comma = value.IndexOf((byte)',');
            consumed = comma < 0 ? value.Length : comma;
            parameter = Ascii.TrimOptionalWhitespace(value[..consumed]);
            return !parameter.IsEmpty && IsSafeTokenValue(parameter);
        }

        private static bool IsToken(ReadOnlySpan<byte> value)
        {
            foreach (byte current in value)
            {
                if (current is not (
                    >= (byte)'0' and <= (byte)'9' or
                    >= (byte)'A' and <= (byte)'Z' or
                    >= (byte)'a' and <= (byte)'z' or
                    (byte)'-' or (byte)'_'))
                {
                    return false;
                }
            }

            return !value.IsEmpty;
        }

        private static bool IsSafeTokenValue(ReadOnlySpan<byte> value)
        {
            foreach (byte current in value)
            {
                if (current is <= 0x20 or >= 0x7f or (byte)'"')
                {
                    return false;
                }
            }

            return true;
        }
    }
}

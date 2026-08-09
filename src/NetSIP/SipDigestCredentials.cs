using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace NetSIP;

/// <summary>
/// A digest credential containing owned H(A1) values.
/// </summary>
public readonly struct SipDigestCredentials
{
    private readonly byte[]? _sha256Ha1;
    private readonly byte[]? _md5Ha1;

    private SipDigestCredentials(byte[]? sha256Ha1, byte[]? md5Ha1)
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
    public static SipDigestCredentials FromPassword(
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
            return new SipDigestCredentials(sha256, md5);
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
    public static SipDigestCredentials FromSha256Ha1(ReadOnlySpan<byte> sha256Ha1)
    {
        return sha256Ha1.Length == 32
            ? new SipDigestCredentials(sha256Ha1.ToArray(), md5Ha1: null)
            : throw new ArgumentException(
                "A SHA-256 H(A1) value must contain 32 bytes.",
                nameof(sha256Ha1));
    }

    /// <summary>Creates a credential from a precomputed 16-byte MD5 H(A1) value.</summary>
    /// <param name="md5Ha1">The binary MD5 digest, not its hexadecimal representation.</param>
    /// <returns>An owned MD5 credential.</returns>
    public static SipDigestCredentials FromMd5Ha1(ReadOnlySpan<byte> md5Ha1)
    {
        return md5Ha1.Length == 16
            ? new SipDigestCredentials(sha256Ha1: null, md5Ha1.ToArray())
            : throw new ArgumentException(
                "An MD5 H(A1) value must contain 16 bytes.",
                nameof(md5Ha1));
    }
}

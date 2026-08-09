using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace NetSIP;

/// <summary>Configuration for <see cref="SipTlsServer"/>.</summary>
public sealed class SipTlsServerOptions
{
    public IPEndPoint ListenEndPoint { get; init; } = new(IPAddress.Any, 5061);

    public required X509Certificate2 ServerCertificate { get; init; }

    public SipServerLimits Limits { get; init; } = new();

    public int Backlog { get; init; } = 128;

    public int MaxConcurrentConnections { get; init; } = 512;

    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan ReadTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan HandlerTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(ListenEndPoint);
        ArgumentNullException.ThrowIfNull(ServerCertificate);
        ArgumentNullException.ThrowIfNull(Limits);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(Backlog);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxConcurrentConnections);
        ValidateTimeout(HandshakeTimeout, nameof(HandshakeTimeout));
        ValidateTimeout(ReadTimeout, nameof(ReadTimeout));
        ValidateTimeout(HandlerTimeout, nameof(HandlerTimeout));
        Limits.Validate();

        if (!ServerCertificate.HasPrivateKey)
        {
            throw new ArgumentException("The server certificate must contain a private key.", nameof(ServerCertificate));
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now < ServerCertificate.NotBefore || now > ServerCertificate.NotAfter)
        {
            throw new ArgumentException("The server certificate is not currently valid.", nameof(ServerCertificate));
        }
    }

    private static void ValidateTimeout(TimeSpan timeout, string name)
    {
        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(name, "Timeouts must be finite and positive.");
        }
    }
}

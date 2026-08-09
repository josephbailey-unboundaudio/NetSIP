using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace NetSIP;

/// <summary>Configuration for <see cref="SipTlsServer"/>.</summary>
public sealed class SipTlsServerOptions
{
    /// <summary>
    /// Gets or initializes the local endpoint to listen on.
    /// Default is any address on port 5061 (standard SIP TLS port).
    /// </summary>
    public IPEndPoint ListenEndPoint { get; init; } = new(IPAddress.Any, 5061);

    /// <summary>
    /// Gets or initializes the TLS server certificate with private key.
    /// This property is required.
    /// </summary>
    public required X509Certificate2 ServerCertificate { get; init; }

    /// <summary>
    /// Gets or initializes the limits for SIP message parsing and framing.
    /// </summary>
    public SipServerLimits Limits { get; init; } = new();

    /// <summary>
    /// Gets or initializes the maximum length of the pending connections queue.
    /// </summary>
    public int Backlog { get; init; } = 128;

    /// <summary>
    /// Gets or initializes the maximum number of concurrent TLS connections.
    /// </summary>
    public int MaxConcurrentConnections { get; init; } = 512;

    /// <summary>
    /// Gets or initializes the maximum time allowed for completing the TLS handshake.
    /// </summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets or initializes the maximum time to wait for data on an idle connection.
    /// </summary>
    public TimeSpan ReadTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or initializes the maximum time allowed for a request handler to complete.
    /// </summary>
    public TimeSpan HandlerTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Validates that all options have valid values and the certificate is usable.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if required properties are null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if numeric values are out of range.</exception>
    /// <exception cref="ArgumentException">Thrown if the certificate is invalid.</exception>
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

        // Ensure certificate has a private key
        if (!ServerCertificate.HasPrivateKey)
        {
            throw new ArgumentException("The server certificate must contain a private key.", nameof(ServerCertificate));
        }

        // Ensure certificate is currently valid
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now < ServerCertificate.NotBefore || now > ServerCertificate.NotAfter)
        {
            throw new ArgumentException("The server certificate is not currently valid.", nameof(ServerCertificate));
        }
    }

    /// <summary>
    /// Validates that a timeout value is finite and positive.
    /// </summary>
    private static void ValidateTimeout(TimeSpan timeout, string name)
    {
        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(name, "Timeouts must be finite and positive.");
        }
    }
}

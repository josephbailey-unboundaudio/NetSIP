using System.Security.Cryptography.X509Certificates;

namespace NetSIP;

/// <summary>Certificate file configuration for PFX or PEM/private-key loading.</summary>
public sealed class SipCertificateOptions
{
    /// <summary>
    /// Gets or initializes the path to a PFX (PKCS#12) certificate file.
    /// Mutually exclusive with PEM options.
    /// </summary>
    public string? PfxPath { get; init; }

    /// <summary>
    /// Gets or initializes the password for the PFX file, if encrypted.
    /// </summary>
    public string? PfxPassword { get; init; }

    /// <summary>
    /// Gets or initializes the path to a PEM-encoded certificate file.
    /// Must be used with <see cref="PemPrivateKeyPath"/>.
    /// </summary>
    public string? PemCertificatePath { get; init; }

    /// <summary>
    /// Gets or initializes the path to a PEM-encoded private key file.
    /// Must be used with <see cref="PemCertificatePath"/>.
    /// </summary>
    public string? PemPrivateKeyPath { get; init; }

    /// <summary>
    /// Gets or initializes the password for the encrypted PEM private key, if applicable.
    /// </summary>
    public string? PemPrivateKeyPassword { get; init; }
}

/// <summary>Loads server certificates without logging certificate passwords or key material.</summary>
public static class SipCertificateLoader
{
    /// <summary>
    /// Loads an X.509 certificate with private key from either PFX or PEM files.
    /// </summary>
    /// <param name="options">The certificate file configuration.</param>
    /// <returns>A loaded certificate with private key.</returns>
    /// <exception cref="ArgumentNullException">Thrown if options is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the configuration is invalid or the certificate has no private key.</exception>
    public static X509Certificate2 Load(SipCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        bool hasPfx = !string.IsNullOrWhiteSpace(options.PfxPath);
        bool hasPemCertificate = !string.IsNullOrWhiteSpace(options.PemCertificatePath);
        bool hasPemKey = !string.IsNullOrWhiteSpace(options.PemPrivateKeyPath);

        // A PEM certificate and key form one source; PFX is the other.
        if (hasPfx == hasPemCertificate || hasPemCertificate != hasPemKey)
        {
            throw new ArgumentException(
                "Configure exactly one certificate source: PfxPath, or both PemCertificatePath and PemPrivateKeyPath.",
                nameof(options));
        }

        X509Certificate2 certificate;
        if (hasPfx)
        {
            certificate = X509CertificateLoader.LoadPkcs12FromFile(
                Path.GetFullPath(options.PfxPath!),
                options.PfxPassword,
                GetKeyStorageFlags());
        }
        else
        {
            X509Certificate2 pemCertificate = string.IsNullOrEmpty(options.PemPrivateKeyPassword)
                ? X509Certificate2.CreateFromPemFile(
                    Path.GetFullPath(options.PemCertificatePath!),
                    Path.GetFullPath(options.PemPrivateKeyPath!))
                : X509Certificate2.CreateFromEncryptedPemFile(
                    Path.GetFullPath(options.PemCertificatePath!),
                    options.PemPrivateKeyPassword,
                    Path.GetFullPath(options.PemPrivateKeyPath!));

            // Re-import on Windows so the private key uses a stable user key container.
            if (OperatingSystem.IsWindows())
            {
                using (pemCertificate)
                {
                    certificate = X509CertificateLoader.LoadPkcs12(
                        pemCertificate.Export(X509ContentType.Pkcs12),
                        password: null,
                        GetKeyStorageFlags());
                }
            }
            else
            {
                certificate = pemCertificate;
            }
        }

        // CreateFromPemFile can return a certificate without a usable matching key.
        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new ArgumentException("The configured certificate does not contain a private key.", nameof(options));
        }

        return certificate;
    }

    /// <summary>
    /// Gets the appropriate key storage flags based on the operating system.
    /// Windows uses UserKeySet, while other platforms use EphemeralKeySet.
    /// </summary>
    private static X509KeyStorageFlags GetKeyStorageFlags()
    {
        return OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
    }
}

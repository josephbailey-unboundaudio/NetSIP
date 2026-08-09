using System.Security.Cryptography.X509Certificates;

namespace NetSIP;

/// <summary>Certificate file configuration for PFX or PEM/private-key loading.</summary>
public sealed class SipCertificateOptions
{
    public string? PfxPath { get; init; }

    public string? PfxPassword { get; init; }

    public string? PemCertificatePath { get; init; }

    public string? PemPrivateKeyPath { get; init; }

    public string? PemPrivateKeyPassword { get; init; }
}

/// <summary>Loads server certificates without logging certificate passwords or key material.</summary>
public static class SipCertificateLoader
{
    public static X509Certificate2 Load(SipCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        bool hasPfx = !string.IsNullOrWhiteSpace(options.PfxPath);
        bool hasPemCertificate = !string.IsNullOrWhiteSpace(options.PemCertificatePath);
        bool hasPemKey = !string.IsNullOrWhiteSpace(options.PemPrivateKeyPath);

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

        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new ArgumentException("The configured certificate does not contain a private key.", nameof(options));
        }

        return certificate;
    }

    private static X509KeyStorageFlags GetKeyStorageFlags() =>
        OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
}

namespace NetSIP;

/// <summary>
/// Certificate file configuration for PFX or PEM/private-key loading.
/// </summary>
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

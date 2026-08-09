namespace NetSIP;

/// <summary>
/// Resolves an owned digest credential for a username.
/// </summary>
public interface ISipDigestCredentialsProvider
{
    /// <summary>Looks up a credential without retaining request-owned data.</summary>
    /// <param name="userName">An owned username decoded as strict UTF-8.</param>
    /// <param name="cancellationToken">A token that cancels credential lookup.</param>
    /// <returns>The matching credential, or <see langword="null"/> for an unknown user.</returns>
    ValueTask<SipDigestCredentials?> GetCredentialAsync(
        string userName,
        CancellationToken cancellationToken);
}

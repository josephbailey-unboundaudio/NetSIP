namespace NetSIP.Authentication
{
    /// <summary>
    /// Stores pre-hashed digest credentials in process memory.
    /// </summary>
    public sealed class InMemorySipDigestCredentialsProvider : ISipDigestCredentialsProvider
    {
        private readonly Dictionary<string, SipDigestCredentials> _credentials;

        /// <summary>Builds an immutable credential store without retaining plaintext passwords.</summary>
        /// <param name="realm">The realm used to calculate H(A1).</param>
        /// <param name="users">Username/password pairs to hash during construction.</param>
        public InMemorySipDigestCredentialsProvider(
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
                    SipDigestCredentials.FromPassword(user.Key, realm, user.Value));
            }
        }

        /// <inheritdoc />
        public ValueTask<SipDigestCredentials?> GetCredentialAsync(
            string userName,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                _credentials.TryGetValue(userName, out SipDigestCredentials credential)
                    ? (SipDigestCredentials?)credential
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
}

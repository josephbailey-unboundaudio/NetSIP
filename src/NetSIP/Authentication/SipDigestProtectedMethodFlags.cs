namespace NetSIP.Authentication
{
    /// <summary>Identifies the SIP methods protected by digest authentication.</summary>
    [Flags]
    public enum SipDigestProtectedMethodFlags
    {
        /// <summary>No methods are protected.</summary>
        None = 0,

        /// <summary>REGISTER requests are protected.</summary>
        Register = 1,

        /// <summary>INVITE requests are protected.</summary>
        Invite = 2
    }
}

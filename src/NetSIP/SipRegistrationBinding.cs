namespace NetSIP;

/// <summary>A registrar binding returned in a successful REGISTER response.</summary>
public readonly struct SipRegistrationBinding
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SipRegistrationBinding"/> struct.
    /// </summary>
    /// <param name="contact">The Contact URI for this binding.</param>
    /// <param name="expires">The remaining seconds until this binding expires.</param>
    /// <exception cref="ArgumentException">Thrown if contact is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if expires is negative.</exception>
    public SipRegistrationBinding(ReadOnlyMemory<byte> contact, int expires)
    {
        if (contact.IsEmpty)
        {
            throw new ArgumentException("A registration binding requires a Contact value.", nameof(contact));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(expires);
        Contact = contact;
        Expires = expires;
    }

    /// <summary>
    /// Gets the Contact URI bytes for this binding.
    /// </summary>
    public ReadOnlyMemory<byte> Contact { get; }

    /// <summary>
    /// Gets the number of seconds until this binding expires.
    /// </summary>
    public int Expires { get; }
}

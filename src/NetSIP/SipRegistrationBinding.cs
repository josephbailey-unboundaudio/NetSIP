namespace NetSIP;

/// <summary>A registrar binding returned in a successful REGISTER response.</summary>
public readonly struct SipRegistrationBinding
{
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

    public ReadOnlyMemory<byte> Contact { get; }

    public int Expires { get; }
}

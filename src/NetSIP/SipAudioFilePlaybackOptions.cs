using System.Net;
using System.Net.Sockets;

namespace NetSIP;

/// <summary>
/// Configures one-shot WAV playback for a SIP dialplan extension.
/// </summary>
public sealed class SipAudioFilePlaybackOptions
{
    /// <summary>Gets the local WAV file loaded and transcoded during construction.</summary>
    public required string AudioFilePath { get; init; }

    /// <summary>Gets the request-URI user routed to playback. The default is *86.</summary>
    public string Extension { get; init; } = "*86";

    /// <summary>Gets the complete Contact value returned by a successful INVITE.</summary>
    public required string Contact { get; init; }

    /// <summary>Gets the local unicast address used to bind RTP sockets.</summary>
    public required IPAddress BindAddress { get; init; }

    /// <summary>Gets the unicast address advertised in the SDP answer.</summary>
    public required IPAddress AdvertisedAddress { get; init; }

    /// <summary>Gets the maximum number of concurrent playback sessions.</summary>
    public int MaxConcurrentSessions { get; init; } = 16;

    /// <summary>Gets the maximum accepted WAV file size. The default is 16 MiB.</summary>
    public int MaxAudioFileBytes { get; init; } = 16 * 1024 * 1024;

    /// <summary>Gets the maximum transcoded playback duration. The default is five minutes.</summary>
    public TimeSpan MaxPlaybackDuration { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets the delay before sending the first RTP packet, allowing the buffered 200 response
    /// to reach the caller. The default is 100 milliseconds.
    /// </summary>
    public TimeSpan StartDelay { get; init; } = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Gets whether the SDP media address must equal the signaling peer address.
    /// This secure default prevents the server from reflecting RTP to a third party.
    /// </summary>
    public bool RequireMediaAddressMatchSignalingPeer { get; init; } = true;

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(AudioFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(Extension);
        ArgumentException.ThrowIfNullOrWhiteSpace(Contact);
        ArgumentNullException.ThrowIfNull(BindAddress);
        ArgumentNullException.ThrowIfNull(AdvertisedAddress);
        if (!IsVisibleAscii(Extension) ||
            Extension.IndexOfAny(['@', ';', '?']) >= 0)
        {
            throw new ArgumentException(
                "The playback extension must contain visible request-URI user characters.",
                nameof(Extension));
        }

        if (!IsSafeHeaderValue(Contact))
        {
            throw new ArgumentException(
                "The playback Contact must contain safe printable ASCII.",
                nameof(Contact));
        }

        if (BindAddress.AddressFamily != AdvertisedAddress.AddressFamily ||
            !IsUnicastOrAny(BindAddress) ||
            !IsUnicast(AdvertisedAddress))
        {
            throw new ArgumentException(
                "RTP bind and advertised addresses must use the same family and the advertised address must be unicast.");
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxConcurrentSessions);
        if (MaxAudioFileBytes is < 44 or > 256 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxAudioFileBytes),
                "MaxAudioFileBytes must be between 44 bytes and 256 MiB.");
        }

        if (MaxPlaybackDuration < TimeSpan.FromMilliseconds(20) ||
            MaxPlaybackDuration > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxPlaybackDuration),
                "MaxPlaybackDuration must be between 20 milliseconds and one hour.");
        }

        if (StartDelay < TimeSpan.Zero || StartDelay > TimeSpan.FromSeconds(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(StartDelay),
                "StartDelay must be between zero and five seconds.");
        }
    }

    private static bool IsVisibleAscii(string value)
    {
        foreach (char current in value)
        {
            if (current is < '!' or > '~')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSafeHeaderValue(string value)
    {
        foreach (char current in value)
        {
            if (current is < ' ' or > '~')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsUnicastOrAny(IPAddress address)
    {
        return address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) ||
            IsUnicast(address);
    }

    internal static bool IsUnicast(IPAddress address)
    {
        if (address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.Broadcast) ||
            address.IsIPv6Multicast)
        {
            return false;
        }

        byte[] bytes = address.GetAddressBytes();
        return address.AddressFamily != AddressFamily.InterNetwork ||
            bytes[0] is < 224 or > 239;
    }
}

using Microsoft.Extensions.Logging;
using NetSIP.Audio;
using NetSIP.Authentication;
using NetSIP.Request;
using NetSIP.Server;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

if (args.Length == 0 || Array.IndexOf(args, "--help") >= 0)
{
    Console.WriteLine(
        """
        NetSIP.Sample
          PFX: --pfx <path> [--password-env <name>]
          PEM: --pem <cert-path> --key <key-path> [--key-password-env <name>]
          Common: [--address <ip>] [--port <port>]

        Password environment variables default to NETSIP_PFX_PASSWORD and
        NETSIP_PEM_KEY_PASSWORD. Passwords and private-key material are never logged.
        Set NETSIP_DIGEST_USERNAME and NETSIP_DIGEST_PASSWORD to protect REGISTER
        and INVITE. NETSIP_DIGEST_REALM defaults to NetSIP. Set
        NETSIP_DIGEST_ALLOW_MD5=true only for legacy client interoperability.
        Set NETSIP_STAR86_WAV and NETSIP_RTP_ADDRESS to answer *86 and stream the
        WAV file as PCMU RTP. NETSIP_RTP_BIND_ADDRESS and NETSIP_STAR86_CONTACT
        are optional overrides.
        """);
    return;
}

Dictionary<string, string> arguments = ParseArguments(args);
string? pfxPath = Get(arguments, "--pfx");
string? pemPath = Get(arguments, "--pem");
string? keyPath = Get(arguments, "--key");
string pfxPasswordEnvironment = Get(arguments, "--password-env") ?? "NETSIP_PFX_PASSWORD";
string pemPasswordEnvironment = Get(arguments, "--key-password-env") ?? "NETSIP_PEM_KEY_PASSWORD";

using X509Certificate2 certificate = SipCertificateLoader.Load(
    new SipCertificateOptions
    {
        PfxPath = pfxPath,
        PfxPassword = pfxPath is null ? null : Environment.GetEnvironmentVariable(pfxPasswordEnvironment),
        PemCertificatePath = pemPath,
        PemPrivateKeyPath = keyPath,
        PemPrivateKeyPassword = pemPath is null ? null : Environment.GetEnvironmentVariable(pemPasswordEnvironment)
    });

IPAddress address = IPAddress.Parse(Get(arguments, "--address") ?? "0.0.0.0");
int port = int.Parse(
    Get(arguments, "--port") ?? "5061",
    System.Globalization.CultureInfo.InvariantCulture);

using ILoggerFactory loggerFactory = LoggerFactory.Create(
    builder => builder.AddSimpleConsole(options => options.SingleLine = true));
ILogger<SipTlsServer> logger = loggerFactory.CreateLogger<SipTlsServer>();
string? inviteRedirect = Environment.GetEnvironmentVariable("NETSIP_INVITE_REDIRECT");
SipDialPlanResult defaultInviteResult = string.IsNullOrWhiteSpace(inviteRedirect)
    ? SipDialPlanResult.Reject(404, "Not Found"u8.ToArray())
    : SipDialPlanResult.Redirect(Encoding.ASCII.GetBytes(inviteRedirect));
ISipDialPlanProcessor dialPlan = new PrefixSipDialPlanProcessor(
    [],
    defaultInviteResult);
SipAudioFileDialPlanProcessor? playbackProcessor = null;
string? star86Wav = Environment.GetEnvironmentVariable("NETSIP_STAR86_WAV");
if (!string.IsNullOrWhiteSpace(star86Wav))
{
    string rtpAddressValue =
        Environment.GetEnvironmentVariable("NETSIP_RTP_ADDRESS") ??
        throw new InvalidOperationException(
            "NETSIP_RTP_ADDRESS is required when NETSIP_STAR86_WAV is set.");
    IPAddress rtpAddress = IPAddress.Parse(rtpAddressValue);
    IPAddress rtpBindAddress = IPAddress.Parse(
        Environment.GetEnvironmentVariable("NETSIP_RTP_BIND_ADDRESS") ??
        rtpAddressValue);
    string contact =
        Environment.GetEnvironmentVariable("NETSIP_STAR86_CONTACT") ??
        $"<sips:playback@{FormatSipHost(rtpAddress)}:{port}>";
    playbackProcessor = new SipAudioFileDialPlanProcessor(
        dialPlan,
        new SipAudioFilePlaybackOptions
        {
            AudioFilePath = star86Wav,
            Contact = contact,
            BindAddress = rtpBindAddress,
            AdvertisedAddress = rtpAddress
        },
        loggerFactory.CreateLogger<SipAudioFileDialPlanProcessor>());
    dialPlan = playbackProcessor;
}

SipInviteRequestHandler inviteHandler = new(
    dialPlan);
ISipRequestHandler applicationHandler = new DefaultSipRequestHandler(
    new RegisterSipRequestHandler(),
    inviteHandler);
string? digestUserName = Environment.GetEnvironmentVariable("NETSIP_DIGEST_USERNAME");
string? digestPassword = Environment.GetEnvironmentVariable("NETSIP_DIGEST_PASSWORD");
if (digestUserName is not null || digestPassword is not null)
{
    if (string.IsNullOrWhiteSpace(digestUserName) || digestPassword is null)
    {
        throw new InvalidOperationException(
            "NETSIP_DIGEST_USERNAME and NETSIP_DIGEST_PASSWORD must both be set.");
    }

    string digestRealm =
        Environment.GetEnvironmentVariable("NETSIP_DIGEST_REALM") ?? "NetSIP";
    bool allowMd5 = string.Equals(
        Environment.GetEnvironmentVariable("NETSIP_DIGEST_ALLOW_MD5"),
        "true",
        StringComparison.OrdinalIgnoreCase);
    InMemorySipDigestCredentialsProvider credentials = new(
        digestRealm,
        [new KeyValuePair<string, string>(digestUserName, digestPassword)]);
    applicationHandler = new SipDigestAuthenticationHandler(
        applicationHandler,
        credentials,
        new SipDigestAuthenticationOptions
        {
            Realm = digestRealm,
            Algorithms = allowMd5
                ? SipDigestAlgorithmFlags.Sha256 | SipDigestAlgorithmFlags.Md5
                : SipDigestAlgorithmFlags.Sha256
        });
}

await using SipTlsServer server = new(
    new SipTlsServerOptions
    {
        ListenEndPoint = new IPEndPoint(address, port),
        ServerCertificate = certificate
    },
    applicationHandler,
    logger);

using CancellationTokenSource shutdown = new();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

try
{
    await server.StartAsync(shutdown.Token);
    try
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, shutdown.Token);
    }
    catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
    {
    }
}
finally
{
    await server.StopAsync();
    if (playbackProcessor is not null)
    {
        await playbackProcessor.DisposeAsync();
    }
}

static Dictionary<string, string> ParseArguments(string[] values)
{
    Dictionary<string, string> result = [with(StringComparer.Ordinal)];
    for (int i = 0; i < values.Length; i += 2)
    {
        if (i + 1 >= values.Length || !values[i].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"Expected a value after '{values[i]}'.");
        }

        result.Add(values[i], values[i + 1]);
    }

    return result;
}

static string? Get(Dictionary<string, string> values, string key)
{
    return values.TryGetValue(key, out string? value) ? value : null;
}

static string FormatSipHost(IPAddress address)
{
    return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
        ? $"[{address}]"
        : address.ToString();
}

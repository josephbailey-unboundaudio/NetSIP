using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using NetSIP;

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

await using SipTlsServer server = new(
    new SipTlsServerOptions
    {
        ListenEndPoint = new IPEndPoint(address, port),
        ServerCertificate = certificate
    },
    new DefaultSipRequestHandler(new RegisterSipRequestHandler()),
    logger);

using CancellationTokenSource shutdown = new();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

await server.StartAsync(shutdown.Token);
try
{
    await Task.Delay(Timeout.InfiniteTimeSpan, shutdown.Token);
}
catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
{
}

await server.StopAsync();

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

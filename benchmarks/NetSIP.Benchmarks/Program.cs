using System.Diagnostics;
using System.Text;
using NetSIP;

const int warmupIterations = 100_000;
const int measuredIterations = 1_000_000;

byte[] request = Encoding.ASCII.GetBytes(
    "OPTIONS sip:service@example.com SIP/2.0\r\n" +
    "Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-1\r\n" +
    "From: <sip:caller@example.com>;tag=abc\r\n" +
    "To: <sip:service@example.com>\r\n" +
    "Call-ID: allocation-proof@example.com\r\n" +
    "CSeq: 1 OPTIONS\r\n" +
    "Content-Length: 0\r\n\r\n");
SipServerLimits limits = new();

int checksum = Run(request, limits, warmupIterations);
GC.Collect();
GC.WaitForPendingFinalizers();
GC.Collect();

long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
long started = Stopwatch.GetTimestamp();
checksum ^= Run(request, limits, measuredIterations);
long elapsedTicks = Stopwatch.GetTimestamp() - started;
long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

double seconds = elapsedTicks / (double)Stopwatch.Frequency;
Console.WriteLine($"Messages: {measuredIterations:N0}");
Console.WriteLine($"Throughput: {measuredIterations / seconds:N0} messages/second");
Console.WriteLine(
    $"Managed allocations: {allocated:N0} bytes ({allocated / (double)measuredIterations:N4} B/message)");
Console.WriteLine($"Checksum: {checksum}");

if (allocated != 0)
{
    Console.Error.WriteLine("The isolated parser loop allocated managed memory after warmup.");
    Environment.ExitCode = 1;
}

static int Run(byte[] message, SipServerLimits limits, int iterations)
{
    int checksum = 0;
    for (int i = 0; i < iterations; i++)
    {
        if (!SipParser.TryParse(message, limits, out SipMessageView parsed, out SipParseError error))
        {
            throw new InvalidOperationException($"Parser failed with {error}.");
        }

        checksum += parsed.Method.Length + parsed.Body.Length + parsed.Raw.Length;
    }

    return checksum;
}

# NetSIP

NetSIP is an allocation-conscious SIP-over-TLS server and byte-oriented SIP
parser for .NET 10 LTS. It provides a reusable library, a runnable host, a
dependency-free test executable, and a deterministic allocation harness.

## Projects

| Project | Purpose |
| --- | --- |
| `src\NetSIP` | TLS server, streaming framer, parser, handlers, response writer, and certificate loader |
| `samples\NetSIP.Sample` | Configuration-driven OPTIONS server |
| `tests\NetSIP.Tests` | Unit and real-network TLS integration tests |
| `benchmarks\NetSIP.Benchmarks` | Warmed parser throughput and allocation measurement |

The solution targets `net10.0` and pins the installed stable `10.0.302` SDK.
.NET 10 is an LTS release.

## Architecture

1. A bounded `Socket` accept loop applies the configured concurrent-connection
   limit before accepting more clients.
2. Each connection uses `NetworkStream`, `SslStream`, and `System.IO.Pipelines`.
   TLS is restricted to TLS 1.2 and TLS 1.3.
3. `SipMessageFramer` walks a possibly segmented `ReadOnlySequence<byte>` to
   find `CRLF CRLF`, validate headers, read `Content-Length`, and isolate exactly
   one message. Fragmented bodies and multiple pipelined messages are supported.
4. `SipParser` validates the complete message from `ReadOnlySpan<byte>` and
   returns a stack-only `SipMessageView`. Headers are enumerated on demand;
   no dictionary or per-message header collection is created.
5. A per-connection `SipRequestContext` is reused for serial dispatch. The
   response writer copies bytes directly into the pooled output pipeline.

The server does not queue messages independently of the pipeline. A handler
must complete before the input buffer is advanced, providing bounded
backpressure and preserving borrowed-buffer lifetimes.

## Run the sample

Create a PFX certificate:

```powershell
dotnet dev-certs https -ep .\server.pfx -p changeit
$env:NETSIP_PFX_PASSWORD = "changeit"
dotnet run --project .\samples\NetSIP.Sample -c Release -- --pfx .\server.pfx --port 5061
```

Or create PEM files with OpenSSL:

```powershell
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 `
  -keyout server.key -out server.pem -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost"
dotnet run --project .\samples\NetSIP.Sample -c Release -- --pem .\server.pem --key .\server.key
```

Encrypted PEM keys are supported with `--key-password-env`; the default
environment variable is `NETSIP_PEM_KEY_PASSWORD`. PFX passwords use
`--password-env`, defaulting to `NETSIP_PFX_PASSWORD`. Passwords and private-key
material are never logged. On Windows, certificates are imported into the user
key store because Schannel cannot authenticate with ephemeral private keys; on
other platforms, ephemeral key storage is used.

The sample accepts `--address` (default `0.0.0.0`) and `--port` (default `5061`).
Press Ctrl+C for graceful shutdown.

## Library usage

```csharp
using System.Net;
using NetSIP;

using var certificate = SipCertificateLoader.Load(
    new SipCertificateOptions
    {
        PfxPath = "server.pfx",
        PfxPassword = Environment.GetEnvironmentVariable("NETSIP_PFX_PASSWORD")
    });

await using var server = new SipTlsServer(
    new SipTlsServerOptions
    {
        ListenEndPoint = new IPEndPoint(IPAddress.Any, 5061),
        ServerCertificate = certificate,
        MaxConcurrentConnections = 512,
        Limits = new SipServerLimits
        {
            MaxStartLineBytes = 2 * 1024,
            MaxHeaderLineBytes = 8 * 1024,
            MaxHeaderBytes = 64 * 1024,
            MaxHeaderCount = 128,
            MaxBodyBytes = 1024 * 1024,
            MaxMessagesPerConnection = 10_000
        }
    },
    new DefaultSipRequestHandler());

await server.StartAsync();
```

`DefaultSipRequestHandler` returns `200 OK` for OPTIONS, copies every Via, and
preserves From, To, Call-ID, and CSeq. It adds a unique To tag when the request
does not contain one. Other methods receive a transaction-preserving
`501 Not Implemented`.

Custom handlers implement `ISipRequestHandler`. Response construction is
synchronous and span-based; the server flushes after the handler completes:

```csharp
public sealed class Handler : ISipRequestHandler
{
    public ValueTask HandleAsync(
        SipRequestContext context,
        CancellationToken cancellationToken)
    {
        SipMessageView request = context.Message;
        if (!context.Response.WriteResponse(
                200,
                "OK"u8,
                request,
                "ready"u8,
                "text/plain"u8))
        {
            context.Response.WriteError(400);
        }

        return ValueTask.CompletedTask;
    }
}
```

`SipMessageView`, `SipHeaderView`, and their spans are borrowed. They are valid
only until `HandleAsync` completes and must not be retained or used by work that
outlives the handler. `SipRequestContext.CopyMessage()` performs the explicit
allocation required when ownership is needed.

## Limits, timeouts, and threat model

Startup validation rejects missing/private-key-less/expired certificates,
invalid endpoints, non-positive connection settings, invalid limits, and
non-finite timeouts. The server enforces:

- start-line, individual header-line, total header, header-count, and body limits;
- maximum messages per connection and maximum concurrent connections;
- TLS handshake, transport-read, and handler timeouts;
- strict CRLF framing, valid header tokens, non-folded headers, numeric
  `Content-Length`, and matching duplicate long/compact Content-Length values.

Malformed messages receive `400 Bad Request`; oversized messages receive
`513 Message Too Large`. When enough of a valid request is available, error
responses preserve its transaction headers. Incomplete-message read timeouts
close silently because no valid SIP transaction is available to receive a 408.
Error responses are sent after TLS establishment when possible, then the
connection is closed.

NetSIP is a transport/parser, not a complete SIP proxy or registrar. It does
not provide digest authentication, authorization, transaction/dialog storage,
rate limiting by identity, client-certificate authentication, certificate
rotation, UDP, or WebSocket transport. Deploy behind appropriate network
controls, use a publicly or privately trusted certificate, keep limits
conservative, and implement application authentication in the handler.

## Allocation boundary

The following application-controlled operations are designed to allocate zero
managed bytes after JIT warmup:

- contiguous `SipParser.TryParse` calls;
- `SipMessageFramer` sequence walking;
- header lookup/enumeration through borrowed ref-struct views;
- default OPTIONS parsing and response serialization into already-available
  pipeline buffers.

The benchmark verifies the isolated parser loop with
`GC.GetAllocatedBytesForCurrentThread`. A representative run on the development
machine processed roughly 2-3 million messages/second and reported exactly
`0 bytes` across 1,000,000 parses after warmup. Throughput is machine-dependent;
the allocation check exits nonzero if the measured loop allocates.

This is **not** a claim that the complete TLS server is zero-allocation.
`Socket`, `SslStream`, pipelines, Tasks/async runtime machinery, cancellation
timers, logging providers, cryptography, and connection tracking may allocate.
NetSIP allocates connection state once per connection and reuses its request
context and timeout sources. A message spanning pipeline segments is copied
through `ArrayPool<byte>` and returned after dispatch; pool growth can allocate.
Calling `CopyMessage`, retaining application state, or allocating in a custom
handler is explicitly outside the parser/serializer guarantee.

Handler timeouts are cooperative: NetSIP cancels the handler token at the
deadline, and handlers are contractually required to observe it. .NET cannot
safely terminate arbitrary user code; an implementation that ignores
cancellation can delay its connection slot and graceful shutdown. This preserves
the borrowed message buffer until the handler actually returns and avoids unsafe
pool reuse.

## Build, test, and benchmark

```powershell
dotnet restore .\NetSIP.slnx
dotnet build .\NetSIP.slnx -c Release --no-restore
dotnet run --project .\tests\NetSIP.Tests -c Release --no-build
dotnet run --project .\benchmarks\NetSIP.Benchmarks -c Release --no-build
```

The test executable has no test-framework package dependency. It exits nonzero
on failure and covers fragmented and segmented framing, pipelining, body
boundaries, limits, raw/case-insensitive headers, PFX/PEM loading, concurrent
real TLS clients, malformed-message responses, and graceful shutdown.

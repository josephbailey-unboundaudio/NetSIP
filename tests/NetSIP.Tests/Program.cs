using NetSIP;
using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

(string Name, Func<Task> Run)[] tests =
[
    ("Parser reads request lines, headers, and bodies", ParserReadsRequest),
    ("Parser reads status lines", ParserReadsResponse),
    ("Parser rejects conflicting Content-Length values", ParserRejectsConflictingContentLength),
    ("Parser enforces limits and malformed headers", ParserEnforcesLimits),
    ("Framer handles every fragmentation boundary", FramerHandlesFragmentation),
    ("Framer handles segmented pipelined messages", FramerHandlesPipelining),
    ("Certificate loader supports PFX and PEM", CertificateLoaderSupportsPfxAndPem),
    ("TLS server handles concurrent OPTIONS clients", TlsServerHandlesConcurrentOptions),
    ("TLS server handles REGISTER requests", TlsServerHandlesRegister),
    ("TLS server rejects invalid REGISTER requests", TlsServerRejectsInvalidRegister),
    ("TLS server expires REGISTER bindings", TlsServerExpiresRegisterBindings),
    ("TLS server orders and bounds REGISTER state", TlsServerOrdersAndBoundsRegisterState),
    ("REGISTER response rejects injected bindings", RegisterResponseRejectsInjectedBindings),
    ("TLS server applies INVITE dialplan", TlsServerAppliesInviteDialPlan),
    ("TLS server validates INVITE before dialplan", TlsServerValidatesInvite),
    ("INVITE response rejects injected dialplan output", InviteResponseRejectsInjectedOutput),
    ("TLS server authenticates INVITE and REGISTER", TlsServerAuthenticatesInviteAndRegister),
    ("TLS server plays *86 WAV audio over RTP", TlsServerPlaysStar86Audio),
    ("TLS server preserves compact transaction headers", TlsServerPreservesCompactHeaders),
    ("TLS server handles pipelined requests with bodies", TlsServerHandlesPipelinedRequests),
    ("TLS server returns errors for malformed input", TlsServerRejectsMalformedInput),
    ("TLS server enforces cooperative handler timeout", TlsServerEnforcesHandlerTimeout),
    ("TLS server shuts down active connections", TlsServerShutsDownConnections)
];

int failures = 0;
foreach ((string name, Func<Task> run) in tests)
{
    try
    {
        await run();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception exception)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {name}");
        Console.Error.WriteLine(exception);
    }
}

Console.WriteLine($"{tests.Length - failures}/{tests.Length} tests passed.");
return failures == 0 ? 0 : 1;

static Task ParserReadsRequest()
{
    byte[] bytes = Bytes(
        "MESSAGE sip:bob@example.com SIP/2.0\r\n" +
        "v: SIP/2.0/TLS client.example.com;branch=z9hG4bK\r\n" +
        "X-Mixed-Case:  raw value \t\r\n" +
        "Content-Length: 5\r\n\r\nhello");

    Assert.True(
        SipParser.TryParse(bytes, new SipServerLimits(), out SipMessageView message, out SipParseError error),
        $"Expected a parsed message, got {error}.");
    Assert.Equal("MESSAGE"u8, message.Method);
    Assert.Equal("sip:bob@example.com"u8, message.RequestUri);
    Assert.Equal("SIP/2.0"u8, message.Version);
    Assert.Equal("hello"u8, message.Body);
    Assert.True(message.TryGetHeader("x-mixed-case"u8, out ReadOnlySpan<byte> value));
    Assert.Equal("raw value"u8, value);

    SipHeaderEnumerator headers = message.GetHeaders();
    bool foundRaw = false;
    while (headers.MoveNext())
    {
        if (headers.Current.Name.SequenceEqual("X-Mixed-Case"u8))
        {
            Assert.Equal("  raw value \t"u8, headers.Current.RawValue);
            foundRaw = true;
        }
    }

    Assert.True(foundRaw);
    return Task.CompletedTask;
}

static Task ParserReadsResponse()
{
    byte[] bytes = Bytes("SIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n");
    Assert.True(
        SipParser.TryParse(bytes, new SipServerLimits(), out SipMessageView message, out SipParseError error),
        $"Expected a parsed response, got {error}.");
    Assert.Equal(SipMessageKind.Response, message.Kind);
    Assert.Equal(486, message.StatusCode);
    Assert.Equal("Busy Here"u8, message.ReasonPhrase);
    return Task.CompletedTask;
}

static Task ParserRejectsConflictingContentLength()
{
    byte[] bytes = Bytes(
        "OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\nl: 1\r\n\r\nx");
    Assert.False(
        SipParser.TryParse(bytes, new SipServerLimits(), out _, out SipParseError error));
    Assert.Equal(SipParseError.InvalidContentLength, error);

    byte[] matching = Bytes(
        "OPTIONS sip:a SIP/2.0\r\nContent-Length: 1\r\nl: 1\r\n\r\nx");
    Assert.True(
        SipParser.TryParse(matching, new SipServerLimits(), out _, out error),
        $"Matching Content-Length headers should parse, got {error}.");
    return Task.CompletedTask;
}

static Task ParserEnforcesLimits()
{
    byte[] folded = Bytes(
        "OPTIONS sip:a SIP/2.0\r\nVia: first\r\n continuation\r\nContent-Length: 0\r\n\r\n");
    Assert.False(SipParser.TryParse(folded, new SipServerLimits(), out _, out SipParseError foldedError));
    Assert.Equal(SipParseError.MalformedHeader, foldedError);

    byte[] injected = Bytes(
        "OPTIONS sip:a SIP/2.0\r\nVia: safe\nInjected: value\r\nContent-Length: 0\r\n\r\n");
    Assert.False(SipParser.TryParse(injected, new SipServerLimits(), out _, out SipParseError injectionError));
    Assert.Equal(SipParseError.MalformedHeader, injectionError);

    byte[] oversizedBody = Bytes(
        "MESSAGE sip:a SIP/2.0\r\nContent-Length: 4\r\n\r\ndata");
    SipServerLimits limits = new() { MaxBodyBytes = 3 };
    Assert.False(SipParser.TryParse(oversizedBody, limits, out _, out SipParseError bodyError));
    Assert.Equal(SipParseError.MessageTooLarge, bodyError);

    byte[] longLine = Bytes(
        "OPTIONS sip:a SIP/2.0\r\nLong: abcdef\r\nContent-Length: 0\r\n\r\n");
    limits = new SipServerLimits { MaxHeaderLineBytes = 8 };
    Assert.False(SipParser.TryParse(longLine, limits, out _, out SipParseError lineError));
    Assert.Equal(SipParseError.MessageTooLarge, lineError);
    return Task.CompletedTask;
}

static Task FramerHandlesFragmentation()
{
    byte[] bytes = Bytes(
        "MESSAGE sip:bob@example.com SIP/2.0\r\n" +
        "Content-Length: 5\r\n\r\nhello");
    SipServerLimits limits = new();

    for (int length = 0; length < bytes.Length; length++)
    {
        ReadOnlySequence<byte> partial = new(bytes.AsMemory(0, length));
        Assert.Equal(
            SipFrameStatus.NeedMoreData,
            SipMessageFramer.TryRead(partial, limits, out _));
    }

    ReadOnlySequence<byte> complete = new(bytes);
    Assert.Equal(
        SipFrameStatus.Complete,
        SipMessageFramer.TryRead(complete, limits, out ReadOnlySequence<byte> framed));
    Assert.Equal(bytes.Length, checked((int)framed.Length));
    return Task.CompletedTask;
}

static Task FramerHandlesPipelining()
{
    byte[] first = Bytes("OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n");
    byte[] second = Bytes("MESSAGE sip:b SIP/2.0\r\nContent-Length: 3\r\n\r\nabc");
    byte[] combined = [.. first, .. second];
    ReadOnlySequence<byte> sequence = SegmentedSequence.Create(
        combined.AsMemory(0, 7),
        combined.AsMemory(7, first.Length - 7 + 4),
        combined.AsMemory(first.Length + 4));
    SipServerLimits limits = new();

    Assert.Equal(
        SipFrameStatus.Complete,
        SipMessageFramer.TryRead(sequence, limits, out ReadOnlySequence<byte> firstFrame));
    Assert.Equal(first.Length, checked((int)firstFrame.Length));

    ReadOnlySequence<byte> remainder = sequence.Slice(firstFrame.End);
    Assert.Equal(
        SipFrameStatus.Complete,
        SipMessageFramer.TryRead(remainder, limits, out ReadOnlySequence<byte> secondFrame));
    Assert.Equal(second.Length, checked((int)secondFrame.Length));
    return Task.CompletedTask;
}

static async Task TlsServerHandlesConcurrentOptions()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(certificate);
    await server.StartAsync();
    int port = server.BoundEndPoint!.Port;

    Task<string>[] clients = new Task<string>[12];
    for (int i = 0; i < clients.Length; i++)
    {
        clients[i] = SendRequestAsync(port, OptionsRequest(i), fragment: i % 2 == 0);
    }

    string[] responses = await Task.WhenAll(clients);
    HashSet<string> tags = [with(StringComparer.Ordinal)];
    foreach (string response in responses)
    {
        Assert.Contains("SIP/2.0 200 OK\r\n", response);
        Assert.Contains("Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-", response);
        Assert.Contains("From: <sip:caller@example.com>;tag=caller\r\n", response);
        Assert.Contains("To: <sip:service@example.com>;tag=", response);
        Assert.Contains("Call-ID: ", response);
        Assert.Contains("CSeq: 1 OPTIONS\r\n", response);
        Assert.Contains("Content-Length: 0\r\n\r\n", response);
        int toStart = response.IndexOf("To:", StringComparison.Ordinal);
        int tagStart = response.IndexOf(";tag=", toStart, StringComparison.Ordinal);
        int tagEnd = response.IndexOf("\r\n", tagStart, StringComparison.Ordinal);
        Assert.True(tags.Add(response[tagStart..tagEnd]), "Each generated To tag must be unique.");
    }

    await server.StopAsync();
}

static async Task TlsServerPreservesCompactHeaders()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(certificate);
    await server.StartAsync();

    string response = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        "OPTIONS sip:service@example.com SIP/2.0\r\n" +
        "v: SIP/2.0/TLS compact.example.com;branch=z9hG4bK-compact\r\n" +
        "f: <sip:caller@example.com>;tag=compact\r\n" +
        "t: \"Sales;tag=west\" <sip:service@example.com>\r\n" +
        "i: compact@example.com\r\n" +
        "CSeq: 7 OPTIONS\r\n" +
        "l: 0\r\n\r\n",
        fragment: false);

    Assert.Contains("SIP/2.0 200 OK\r\n", response);
    Assert.Contains("Via: SIP/2.0/TLS compact.example.com;branch=z9hG4bK-compact\r\n", response);
    Assert.Contains("From: <sip:caller@example.com>;tag=compact\r\n", response);
    Assert.Contains("To: \"Sales;tag=west\" <sip:service@example.com>;tag=", response);
    Assert.Contains("Call-ID: compact@example.com\r\n", response);
    await server.StopAsync();
}

static async Task TlsServerHandlesRegister()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(
        certificate,
        new RegisterSipRequestHandler());
    await server.StartAsync();

    string response = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(
            "Contact: <sip:alice@client.example.com;transport=tls>\r\n" +
            "Expires: 3600\r\n"),
        fragment: true);
    Assert.Contains("SIP/2.0 200 OK\r\n", response);
    Assert.Contains(
        "Contact: <sip:alice@client.example.com;transport=tls>;expires=",
        response);
    Assert.Contains("CSeq: 2 REGISTER\r\n", response);

    string queryWithBinding = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(string.Empty, cseq: 3),
        fragment: false);
    Assert.Contains(
        "Contact: <sip:alice@client.example.com;transport=tls>;expires=",
        queryWithBinding);

    string multipleResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(
            "Contact: \"Desk, Alice\" <sip:*97@client.example.com>;expires=120, " +
            "<sips:alice@backup.example.com>;expires=180\r\n",
            cseq: 4),
        fragment: false);
    Assert.Contains(
        "Contact: \"Desk, Alice\" <sip:*97@client.example.com>;expires=",
        multipleResponse);
    Assert.Contains(
        "Contact: <sips:alice@backup.example.com>;expires=",
        multipleResponse);

    string wildcardResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("Contact: *\r\nExpires: 0\r\n", cseq: 5),
        fragment: false);
    Assert.Contains("SIP/2.0 200 OK\r\n", wildcardResponse);
    Assert.DoesNotContain("Contact:", wildcardResponse);

    string queryResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(string.Empty, cseq: 6),
        fragment: false);
    Assert.Contains("SIP/2.0 200 OK\r\n", queryResponse);
    Assert.DoesNotContain("Contact:", queryResponse);
    await server.StopAsync();
}

static async Task TlsServerRejectsInvalidRegister()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(
        certificate,
        new RegisterSipRequestHandler());
    await server.StartAsync();

    string wildcardResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("Contact: *\r\nExpires: 60\r\n"),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", wildcardResponse);

    string cseqResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("Contact: <sip:alice@client.example.com>\r\n")
            .Replace("CSeq: 2 REGISTER", "CSeq: 2 OPTIONS", StringComparison.Ordinal),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", cseqResponse);

    string malformedContactResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("Contact: not-a-uri\r\n"),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", malformedContactResponse);

    string invalidExpirationResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("Contact: <sip:alice@client.example.com>;expires=-1\r\n"),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", invalidExpirationResponse);

    string briefExpirationResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("Contact: <sip:alice@client.example.com>;expires=30\r\n"),
        fragment: false);
    Assert.Contains("SIP/2.0 423 Interval Too Brief\r\n", briefExpirationResponse);
    Assert.Contains("Min-Expires: 90\r\n", briefExpirationResponse);

    string duplicateCSeqResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("CSeq: 3 REGISTER\r\nContact: <sip:alice@client.example.com>\r\n"),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", duplicateCSeqResponse);
    await server.StopAsync();
}

static async Task TlsServerExpiresRegisterBindings()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    AdjustableTimeProvider clock = new(
        new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
    RegisterSipRequestHandler handler = new(
        new SipRegisterHandlerOptions
        {
            MinimumExpirationSeconds = 1,
            DefaultExpirationSeconds = 60,
            MaximumExpirationSeconds = 3600
        },
        clock);
    await using SipTlsServer server = CreateServer(certificate, handler);
    await server.StartAsync();

    string registered = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest("Contact: <sip:alice@client.example.com>;expires=60\r\n"),
        fragment: false);
    Assert.Contains("Contact: <sip:alice@client.example.com>;expires=60\r\n", registered);

    clock.Advance(TimeSpan.FromSeconds(61));
    string expired = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(string.Empty, cseq: 3),
        fragment: false);
    Assert.DoesNotContain("Contact:", expired);
    await server.StopAsync();
}

static async Task TlsServerOrdersAndBoundsRegisterState()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    AdjustableTimeProvider clock = new(
        new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
    RegisterSipRequestHandler handler = new(
        new SipRegisterHandlerOptions
        {
            MinimumExpirationSeconds = 1,
            DefaultExpirationSeconds = 60,
            MaximumExpirationSeconds = 60,
            MaxAddressesOfRecord = 1,
            MaxBindingsPerAddress = 2,
            MaxStoredBytes = 2048
        },
        clock);
    await using SipTlsServer server = CreateServer(certificate, handler);
    await server.StartAsync();

    string registered = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(
            "Contact: \"Desk\" <sip:%61lice@CLIENT.example.com;Transport=TCP>\r\n"),
        fragment: false);
    Assert.Contains("SIP/2.0 200 OK\r\n", registered);

    string stale = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(
            "Contact: <sip:alice@client.example.com>;expires=0\r\n",
            cseq: 1),
        fragment: false);
    Assert.Contains("SIP/2.0 500 Server Internal Error\r\n", stale);

    string stillRegistered = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(string.Empty, cseq: 3),
        fragment: false);
    Assert.Contains(
        "Contact: \"Desk\" <sip:%61lice@CLIENT.example.com;Transport=TCP>;expires=",
        stillRegistered);

    string removed = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(
            "Contact: <sip:alice@client.example.com;transport=tcp>;expires=0\r\n",
            cseq: 4),
        fragment: false);
    Assert.DoesNotContain("Contact:", removed);

    clock.Advance(TimeSpan.FromSeconds(61));
    string reclaimed = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(
            "Contact: <sip:bob@client.example.com>\r\n",
            addressOfRecord: "sip:bob@example.com",
            callId: "bob-register@example.com"),
        fragment: false);
    Assert.Contains("SIP/2.0 200 OK\r\n", reclaimed);

    string missingCallId = RegisterRequest(
        "Contact: <sip:mallory@client.example.com>\r\n",
        addressOfRecord: "sip:mallory@example.com",
        callId: "missing@example.com")
        .Replace("Call-ID: missing@example.com\r\n", string.Empty, StringComparison.Ordinal);
    string rejected = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        missingCallId,
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", rejected);
    await server.StopAsync();
}

static async Task RegisterResponseRejectsInjectedBindings()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(
        certificate,
        new UnsafeBindingHandler());
    await server.StartAsync();

    string response = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        RegisterRequest(string.Empty),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", response);
    Assert.DoesNotContain("Injected:", response);
    await server.StopAsync();
}

static async Task TlsServerAppliesInviteDialPlan()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    SipDialPlanResult answer = SipDialPlanResult.Answer(
        Bytes("sips:agent@example.com"),
        Bytes("v=0\r\ns=NetSIP\r\n"),
        Bytes("application/sdp"));
    PrefixSipDialPlanProcessor dialPlan = new(
        [
            new SipDialPlanRule(
                "12",
                SipDialPlanResult.Redirect(Bytes("sips:gateway@example.com"))),
            new SipDialPlanRule("1234", answer),
            new SipDialPlanRule(
                "911",
                SipDialPlanResult.Reject(403, Bytes("Forbidden"))),
            new SipDialPlanRule(
                "example",
                SipDialPlanResult.Reject(486, Bytes("Busy Here")))
        ],
        SipDialPlanResult.Reject(404, Bytes("Not Found")));
    SipInviteRequestHandler inviteHandler = new(dialPlan);
    await using SipTlsServer server = CreateServer(
        certificate,
        new DefaultSipRequestHandler(
            registerHandler: null,
            inviteHandler));
    await server.StartAsync();

    string options = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        OptionsRequest(700),
        fragment: false);
    Assert.Contains("Allow: OPTIONS, INVITE\r\n", options);

    string answered = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("12345"),
        fragment: true);
    Assert.Contains("SIP/2.0 200 OK\r\n", answered);
    Assert.Contains("Contact: sips:agent@example.com\r\n", answered);
    Assert.Contains("Content-Type: application/sdp\r\n", answered);
    Assert.Contains("\r\n\r\nv=0\r\ns=NetSIP\r\n", answered);

    string redirected = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("12999"),
        fragment: false);
    Assert.Contains("SIP/2.0 302 Moved Temporarily\r\n", redirected);
    Assert.Contains("Contact: sips:gateway@example.com\r\n", redirected);

    string rejected = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("911"),
        fragment: false);
    Assert.Contains("SIP/2.0 403 Forbidden\r\n", rejected);

    string missing = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("555"),
        fragment: false);
    Assert.Contains("SIP/2.0 404 Not Found\r\n", missing);

    string hostOnly = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("555").Replace(
            "INVITE sip:555@example.com SIP/2.0",
            "INVITE sip:example.com SIP/2.0",
            StringComparison.Ordinal),
        fragment: false);
    Assert.Contains("SIP/2.0 404 Not Found\r\n", hostOnly);

    string userMatched = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("example"),
        fragment: false);
    Assert.Contains("SIP/2.0 486 Busy Here\r\n", userMatched);
    await server.StopAsync();
}

static async Task TlsServerValidatesInvite()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    CountingDialPlanProcessor dialPlan = new(
        SipDialPlanResult.Reject(486, Bytes("Busy Here")));
    await using SipTlsServer server = CreateServer(
        certificate,
        new SipInviteRequestHandler(dialPlan));
    await server.StartAsync();

    string exhausted = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("100").Replace(
            "Max-Forwards: 70",
            "Max-Forwards: 0",
            StringComparison.Ordinal),
        fragment: false);
    Assert.Contains("SIP/2.0 483 Too Many Hops\r\n", exhausted);

    string invalidCSeq = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("100").Replace(
            "CSeq: 1 INVITE",
            "CSeq: 1 OPTIONS",
            StringComparison.Ordinal),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", invalidCSeq);

    string missingContact = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("100").Replace(
            "Contact: <sips:caller@client.example.com>\r\n",
            string.Empty,
            StringComparison.Ordinal),
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", missingContact);
    Assert.Equal(0, dialPlan.Calls);
    await server.StopAsync();
}

static async Task InviteResponseRejectsInjectedOutput()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(
        certificate,
        new SipInviteRequestHandler(new UnsafeDialPlanProcessor()));
    await server.StartAsync();

    string response = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        InviteRequest("100"),
        fragment: false);
    Assert.Contains("SIP/2.0 500 Server Internal Error\r\n", response);
    Assert.DoesNotContain("Injected:", response);
    await server.StopAsync();
}

static async Task TlsServerAuthenticatesInviteAndRegister()
{
    const string realm = "netsip.example";
    const string userName = "alice";
    const string password = "correct horse battery staple";
    using X509Certificate2 certificate = CreateServerCertificate();
    AdjustableTimeProvider clock = new(
        new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
    CountingDialPlanProcessor dialPlan = new(
        SipDialPlanResult.Reject(486, Bytes("Busy Here")));
    ISipRequestHandler application = new DefaultSipRequestHandler(
        new RegisterSipRequestHandler(),
        new SipInviteRequestHandler(dialPlan));
    InMemorySipDigestCredentialsProvider credentials = new(
        realm,
        [new KeyValuePair<string, string>(userName, password)]);
    SipDigestAuthenticationHandler authenticated = new(
        application,
        credentials,
        new SipDigestAuthenticationOptions
        {
            Realm = realm,
            Algorithms = SipDigestAlgorithmFlags.Sha256 | SipDigestAlgorithmFlags.Md5,
            NonceLifetime = TimeSpan.FromMinutes(1),
            MaxTrackedAuthentications = 2
        },
        timeProvider: clock);
    await using SipTlsServer server = CreateServer(certificate, authenticated);
    await server.StartAsync();

    string options = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        OptionsRequest(900),
        fragment: false);
    Assert.Contains("SIP/2.0 200 OK\r\n", options);

    string invite = InviteRequest("100");
    string inviteChallenge = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        invite,
        fragment: false);
    Assert.Contains("SIP/2.0 401 Unauthorized\r\n", inviteChallenge);
    Assert.Contains("algorithm=SHA-256", inviteChallenge);
    Assert.Contains("algorithm=MD5", inviteChallenge);
    Assert.Equal(0, dialPlan.Calls);

    string inviteNonce = GetDigestNonce(inviteChallenge, "SHA-256");
    string inviteAuthorization = CreateDigestAuthorization(
        userName,
        realm,
        password,
        inviteNonce,
        "INVITE",
        "sip:100@example.com",
        "SHA-256",
        includeAlgorithm: true);
    string wrongPasswordAuthorization = CreateDigestAuthorization(
        userName,
        realm,
        "wrong password",
        inviteNonce,
        "INVITE",
        "sip:100@example.com",
        "SHA-256",
        includeAlgorithm: true);
    string wrongPassword = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(invite, wrongPasswordAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 401 Unauthorized\r\n", wrongPassword);
    Assert.Equal(0, dialPlan.Calls);

    string unknownUserAuthorization = CreateDigestAuthorization(
        "mallory",
        realm,
        "unknown password",
        inviteNonce,
        "INVITE",
        "sip:100@example.com",
        "SHA-256",
        includeAlgorithm: true);
    string unknownUser = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(invite, unknownUserAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 401 Unauthorized\r\n", unknownUser);
    Assert.Equal(0, dialPlan.Calls);

    string authorizedInvite = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(invite, inviteAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 486 Busy Here\r\n", authorizedInvite);
    Assert.Equal(1, dialPlan.Calls);

    string duplicateAuthorization = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(
            AddAuthorization(invite, inviteAuthorization),
            inviteAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 401 Unauthorized\r\n", duplicateAuthorization);
    Assert.Equal(1, dialPlan.Calls);

    string replayAuthorization = CreateDigestAuthorization(
        userName,
        realm,
        password,
        inviteNonce.ToUpperInvariant(),
        "INVITE",
        "sip:100@example.com",
        "SHA-256",
        includeAlgorithm: true);
    string replay = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(invite, replayAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 401 Unauthorized\r\n", replay);
    Assert.Equal(1, dialPlan.Calls);

    string register = RegisterRequest(
        "Contact: <sip:alice@client.example.com>\r\n");
    string registerChallenge = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        register,
        fragment: false);
    string registerNonce = GetDigestNonce(registerChallenge, "MD5");
    string registerAuthorization = CreateDigestAuthorization(
        userName,
        realm,
        password,
        registerNonce,
        "REGISTER",
        "sip:example.com",
        "MD5",
        includeAlgorithm: false);
    string authorizedRegister = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(register, registerAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 200 OK\r\n", authorizedRegister);

    string capacityChallenge = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        invite,
        fragment: false);
    string capacityNonce = GetDigestNonce(capacityChallenge, "SHA-256");
    string capacityAuthorization = CreateDigestAuthorization(
        userName,
        realm,
        password,
        capacityNonce,
        "INVITE",
        "sip:100@example.com",
        "SHA-256",
        includeAlgorithm: true);
    string capacityRejected = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(invite, capacityAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 401 Unauthorized\r\n", capacityRejected);
    Assert.Equal(1, dialPlan.Calls);

    string staleNonce = GetDigestNonce(replay, "SHA-256");
    clock.Advance(TimeSpan.FromSeconds(61));
    string staleAuthorization = CreateDigestAuthorization(
        userName,
        realm,
        password,
        staleNonce,
        "INVITE",
        "sip:100@example.com",
        "SHA-256",
        includeAlgorithm: true);
    string stale = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        AddAuthorization(invite, staleAuthorization),
        fragment: false);
    Assert.Contains("SIP/2.0 401 Unauthorized\r\n", stale);
    Assert.Contains("stale=true", stale);
    Assert.Equal(1, dialPlan.Calls);
    await server.StopAsync();
}

static async Task TlsServerPlaysStar86Audio()
{
    string wavPath = Path.Combine(
        Path.GetTempPath(),
        $"netsip-playback-{Guid.NewGuid():N}.wav");
    try
    {
        File.WriteAllBytes(wavPath, CreateTestWav(sampleCount: 321));
        using X509Certificate2 certificate = CreateServerCertificate();
        using UdpClient rtpReceiver = new(
            new IPEndPoint(IPAddress.Loopback, 0));
        int remoteRtpPort = ((IPEndPoint)rtpReceiver.Client.LocalEndPoint!).Port;
        PrefixSipDialPlanProcessor fallback = new(
            [],
            SipDialPlanResult.Reject(404, Bytes("Not Found")));
        await using SipAudioFileDialPlanProcessor playback = new(
            fallback,
            new SipAudioFilePlaybackOptions
            {
                AudioFilePath = wavPath,
                Contact = "<sips:playback@127.0.0.1>",
                BindAddress = IPAddress.Loopback,
                AdvertisedAddress = IPAddress.Loopback,
                StartDelay = TimeSpan.FromMilliseconds(10),
                MaxConcurrentSessions = 1
            });
        await using SipTlsServer server = CreateServer(
            certificate,
            new SipInviteRequestHandler(playback));
        await server.StartAsync();

        string response = await SendRequestAsync(
            server.BoundEndPoint!.Port,
            InviteRequestWithSdp("*86", remoteRtpPort, IPAddress.Loopback),
            fragment: true);
        Assert.Contains("SIP/2.0 200 OK\r\n", response);
        Assert.Contains("Content-Type: application/sdp\r\n", response);
        Assert.Contains("m=audio ", response);
        Assert.Contains(" RTP/AVP 0\r\n", response);
        Assert.Contains("a=sendonly\r\n", response);

        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        UdpReceiveResult rtp = await rtpReceiver.ReceiveAsync(timeout.Token);
        Assert.Equal(172, rtp.Buffer.Length);
        Assert.Equal((byte)0x80, rtp.Buffer[0]);
        Assert.Equal((byte)0x80, rtp.Buffer[1]);
        Assert.True(
            rtp.Buffer.AsSpan(12).ContainsAnyExcept((byte)0xff),
            "The RTP payload should contain transcoded audio, not only mu-law silence.");
        UdpReceiveResult secondRtp = await rtpReceiver.ReceiveAsync(timeout.Token);
        UdpReceiveResult finalRtp = await rtpReceiver.ReceiveAsync(timeout.Token);
        Assert.Equal(172, secondRtp.Buffer.Length);
        Assert.Equal(13, finalRtp.Buffer.Length);
        Assert.Equal((byte)0, finalRtp.Buffer[1]);

        string unsafeMediaTarget = await SendRequestAsync(
            server.BoundEndPoint.Port,
            InviteRequestWithSdp(
                "*86",
                remoteRtpPort,
                IPAddress.Parse("192.0.2.10")),
            fragment: false);
        Assert.Contains("SIP/2.0 488 Not Acceptable Here\r\n", unsafeMediaTarget);

        string incompatibleDirection = await SendRequestAsync(
            server.BoundEndPoint.Port,
            InviteRequestWithSdp("*86", remoteRtpPort, IPAddress.Loopback).Replace(
                "a=recvonly\r\n",
                "a=sendonly\r\n",
                StringComparison.Ordinal),
            fragment: false);
        Assert.Contains("SIP/2.0 488 Not Acceptable Here\r\n", incompatibleDirection);

        string multipleMediaSections = await SendRequestAsync(
            server.BoundEndPoint.Port,
            InviteRequestWithSdp("*86", remoteRtpPort, IPAddress.Loopback).Replace(
                "m=audio ",
                "m=video 4000 RTP/AVP 31\r\nm=audio ",
                StringComparison.Ordinal),
            fragment: false);
        Assert.Contains("SIP/2.0 488 Not Acceptable Here\r\n", multipleMediaSections);

        string fallbackResponse = await SendRequestAsync(
            server.BoundEndPoint.Port,
            InviteRequestWithSdp("100", remoteRtpPort, IPAddress.Loopback),
            fragment: false);
        Assert.Contains("SIP/2.0 404 Not Found\r\n", fallbackResponse);
        await server.StopAsync();
    }
    finally
    {
        File.Delete(wavPath);
    }
}

static async Task TlsServerRejectsMalformedInput()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(certificate);
    await server.StartAsync();

    string response = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        "OPTIONS sip:a SIP/2.0\r\nBroken\r\n\r\n",
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", response);
    Assert.Contains("Connection: close\r\n", response);

    string transactionResponse = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        "OPTIONS sip:service@example.com SIP/2.0\r\n" +
        "Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-malformed\r\n" +
        "From: <sip:caller@example.com>;tag=caller\r\n" +
        "To: <sip:service@example.com>\r\n" +
        "Call-ID: malformed@example.com\r\n" +
        "CSeq: 9 OPTIONS\r\n" +
        "Broken\r\n" +
        "Content-Length: 0\r\n\r\n",
        fragment: false);
    Assert.Contains("SIP/2.0 400 Bad Request\r\n", transactionResponse);
    Assert.Contains("Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-malformed\r\n", transactionResponse);
    Assert.Contains("Call-ID: malformed@example.com\r\n", transactionResponse);
    await server.StopAsync();
}

static async Task TlsServerHandlesPipelinedRequests()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(certificate);
    await server.StartAsync();

    using TcpClient client = new();
    await client.ConnectAsync(IPAddress.Loopback, server.BoundEndPoint!.Port);
#pragma warning disable CA5359 // The isolated client connects only to its locally generated test server.
    using SslStream tls = new(
        client.GetStream(),
        leaveInnerStreamOpen: false,
        static (_, _, _, _) => true);
#pragma warning restore CA5359
    await tls.AuthenticateAsClientAsync(
        new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        });

    string first = OptionsRequest(100).Replace(
        "Content-Length: 0\r\n\r\n",
        "Content-Length: 3\r\n\r\nabc",
        StringComparison.Ordinal);
    byte[] pipelined = Bytes(first + OptionsRequest(101));
    await tls.WriteAsync(pipelined);
    await tls.FlushAsync();

    byte[] response = new byte[8192];
    int total = 0;
    using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
    while (CountOccurrences(response.AsSpan(0, total), "SIP/2.0 200 OK\r\n"u8) < 2)
    {
        int read = await tls.ReadAsync(response.AsMemory(total), timeout.Token);
        Assert.True(read > 0, "The server closed before both pipelined responses arrived.");
        total += read;
    }

    Assert.Equal(2, CountOccurrences(response.AsSpan(0, total), "SIP/2.0 200 OK\r\n"u8));
    await server.StopAsync();
}

static async Task TlsServerShutsDownConnections()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = CreateServer(certificate);
    await server.StartAsync();

    using TcpClient client = new();
    await client.ConnectAsync(IPAddress.Loopback, server.BoundEndPoint!.Port);
#pragma warning disable CA5359 // The isolated client connects only to its locally generated test server.
    using SslStream tls = new(
        client.GetStream(),
        leaveInnerStreamOpen: false,
        static (_, _, _, _) => true);
#pragma warning restore CA5359
    await tls.AuthenticateAsClientAsync(
        new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        });

    await server.StopAsync().WaitAsync(TimeSpan.FromSeconds(5));
}

static async Task TlsServerEnforcesHandlerTimeout()
{
    using X509Certificate2 certificate = CreateServerCertificate();
    await using SipTlsServer server = new(
        new SipTlsServerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ServerCertificate = certificate,
            HandshakeTimeout = TimeSpan.FromSeconds(5),
            ReadTimeout = TimeSpan.FromSeconds(5),
            HandlerTimeout = TimeSpan.FromMilliseconds(50)
        },
        new WaitingHandler());
    await server.StartAsync();

    string response = await SendRequestAsync(
        server.BoundEndPoint!.Port,
        OptionsRequest(500),
        fragment: false);
    Assert.Contains("SIP/2.0 500 Server Internal Error\r\n", response);
    Assert.Contains("Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-500\r\n", response);
    Assert.Contains("Call-ID: 500@example.com\r\n", response);
    Assert.Contains("Connection: close\r\n", response);
    await server.StopAsync();
}

static SipTlsServer CreateServer(
    X509Certificate2 certificate,
    ISipRequestHandler? handler = null)
{
    return new(
        new SipTlsServerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ServerCertificate = certificate,
            HandshakeTimeout = TimeSpan.FromSeconds(5),
            ReadTimeout = TimeSpan.FromSeconds(5),
            HandlerTimeout = TimeSpan.FromSeconds(5),
            MaxConcurrentConnections = 32
        },
        handler ?? new DefaultSipRequestHandler());
}

static Task CertificateLoaderSupportsPfxAndPem()
{
    using X509Certificate2 source = CreateEphemeralServerCertificate();
    using RSA privateKey = source.GetRSAPrivateKey()
        ?? throw new InvalidOperationException("Generated certificate has no RSA private key.");
    string directory = Path.Combine(Path.GetTempPath(), $"netsip-cert-{Guid.NewGuid():N}");
    string pfxPath = Path.Combine(directory, "server.pfx");
    string certPath = Path.Combine(directory, "server.pem");
    string keyPath = Path.Combine(directory, "server.key");
    _ = Directory.CreateDirectory(directory);

    try
    {
        File.WriteAllBytes(pfxPath, source.Export(X509ContentType.Pkcs12, "test-password"));
        File.WriteAllText(certPath, source.ExportCertificatePem());
        File.WriteAllText(keyPath, privateKey.ExportPkcs8PrivateKeyPem());

        using X509Certificate2 pfx = SipCertificateLoader.Load(
            new SipCertificateOptions
            {
                PfxPath = pfxPath,
                PfxPassword = "test-password"
            });
        using X509Certificate2 pem = SipCertificateLoader.Load(
            new SipCertificateOptions
            {
                PemCertificatePath = certPath,
                PemPrivateKeyPath = keyPath
            });
        Assert.True(pfx.HasPrivateKey);
        Assert.True(pem.HasPrivateKey);
    }
    finally
    {
        File.Delete(pfxPath);
        File.Delete(certPath);
        File.Delete(keyPath);
        Directory.Delete(directory);
    }

    return Task.CompletedTask;
}

static async Task<string> SendRequestAsync(int port, string request, bool fragment)
{
    using TcpClient client = new();
    await client.ConnectAsync(IPAddress.Loopback, port);
#pragma warning disable CA5359 // The isolated client connects only to its locally generated test server.
    using SslStream tls = new(
        client.GetStream(),
        leaveInnerStreamOpen: false,
        static (_, _, _, _) => true);
#pragma warning restore CA5359
    await tls.AuthenticateAsClientAsync(
        new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        });

    byte[] requestBytes = Bytes(request);
    if (fragment)
    {
        int midpoint = requestBytes.Length / 2;
        await tls.WriteAsync(requestBytes.AsMemory(0, midpoint));
        await tls.FlushAsync();
        await Task.Yield();
        await tls.WriteAsync(requestBytes.AsMemory(midpoint));
    }
    else
    {
        await tls.WriteAsync(requestBytes);
    }

    await tls.FlushAsync();

    byte[] response = new byte[4096];
    int total = 0;
    using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
    while (total < response.Length)
    {
        int read = await tls.ReadAsync(response.AsMemory(total), timeout.Token);
        if (read == 0)
        {
            break;
        }

        total += read;
        int headerEnd = response.AsSpan(0, total).IndexOf("\r\n\r\n"u8);
        if (headerEnd >= 0 &&
            TryReadContentLength(
                response.AsSpan(0, headerEnd),
                out int contentLength) &&
            total >= headerEnd + 4 + contentLength)
        {
            break;
        }
    }

    return Encoding.ASCII.GetString(response, 0, total);
}

static bool TryReadContentLength(
    ReadOnlySpan<byte> headers,
    out int contentLength)
{
    ReadOnlySpan<byte> name = "Content-Length:"u8;
    for (int index = 0; index <= headers.Length - name.Length; index++)
    {
        bool lineStart = index == 0 ||
            index >= 2 &&
            headers[(index - 2)..index].SequenceEqual("\r\n"u8);
        if (!lineStart ||
            !headers.Slice(index, name.Length).SequenceEqual(name))
        {
            continue;
        }

        ReadOnlySpan<byte> value = headers[(index + name.Length)..];
        int lineEnd = value.IndexOf("\r\n"u8);
        if (lineEnd >= 0)
        {
            value = value[..lineEnd];
        }

        return int.TryParse(
            Encoding.ASCII.GetString(value),
            out contentLength);
    }

    contentLength = 0;
    return false;
}

static string OptionsRequest(int id)
{
    return "OPTIONS sip:service@example.com SIP/2.0\r\n" +
    $"Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-{id}\r\n" +
    "From: <sip:caller@example.com>;tag=caller\r\n" +
    "To: <sip:service@example.com>\r\n" +
    $"Call-ID: {id}@example.com\r\n" +
    "CSeq: 1 OPTIONS\r\n" +
    "Content-Length: 0\r\n\r\n";
}

static string RegisterRequest(
    string registrationHeaders,
    int cseq = 2,
    string addressOfRecord = "sip:alice@example.com",
    string callId = "register@example.com")
{
    return "REGISTER sip:example.com SIP/2.0\r\n" +
    "Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-register\r\n" +
    $"From: <{addressOfRecord}>;tag=register-client\r\n" +
    $"To: <{addressOfRecord}>\r\n" +
    $"Call-ID: {callId}\r\n" +
    $"CSeq: {cseq} REGISTER\r\n" +
    registrationHeaders +
    "Content-Length: 0\r\n\r\n";
}

static string InviteRequest(string destination)
{
    return $"INVITE sip:{destination}@example.com SIP/2.0\r\n" +
    "Via: SIP/2.0/TLS client.example.com;branch=z9hG4bK-invite\r\n" +
    "Max-Forwards: 70\r\n" +
    "From: <sip:caller@example.com>;tag=invite-client\r\n" +
    $"To: <sip:{destination}@example.com>\r\n" +
    "Call-ID: invite@example.com\r\n" +
    "CSeq: 1 INVITE\r\n" +
    "Contact: <sips:caller@client.example.com>\r\n" +
    "Content-Length: 0\r\n\r\n";
}

static string InviteRequestWithSdp(
    string destination,
    int mediaPort,
    IPAddress mediaAddress)
{
    string addressType = mediaAddress.AddressFamily == AddressFamily.InterNetwork
        ? "IP4"
        : "IP6";
    string sdp =
        "v=0\r\n" +
        $"o=test 1 1 IN {addressType} {mediaAddress}\r\n" +
        "s=NetSIP test\r\n" +
        $"c=IN {addressType} {mediaAddress}\r\n" +
        "t=0 0\r\n" +
        $"m=audio {mediaPort.ToString(System.Globalization.CultureInfo.InvariantCulture)} RTP/AVP 0\r\n" +
        "a=rtpmap:0 PCMU/8000\r\n" +
        "a=recvonly\r\n";
    return InviteRequest(destination).Replace(
        "Content-Length: 0\r\n\r\n",
        $"Content-Type: application/sdp\r\n" +
        $"Content-Length: {Encoding.ASCII.GetByteCount(sdp)}\r\n\r\n{sdp}",
        StringComparison.Ordinal);
}

static byte[] CreateTestWav(int sampleCount)
{
    byte[] wav = new byte[44 + (sampleCount * sizeof(short))];
    "RIFF"u8.CopyTo(wav);
    BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(4), wav.Length - 8);
    "WAVEfmt "u8.CopyTo(wav.AsSpan(8));
    BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(16), 16);
    BinaryPrimitives.WriteUInt16LittleEndian(wav.AsSpan(20), 1);
    BinaryPrimitives.WriteUInt16LittleEndian(wav.AsSpan(22), 1);
    BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(24), 8000);
    BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(28), 16000);
    BinaryPrimitives.WriteUInt16LittleEndian(wav.AsSpan(32), 2);
    BinaryPrimitives.WriteUInt16LittleEndian(wav.AsSpan(34), 16);
    "data"u8.CopyTo(wav.AsSpan(36));
    BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(40), sampleCount * sizeof(short));
    for (int index = 0; index < sampleCount; index++)
    {
        short sample = (short)(Math.Sin(index * Math.Tau * 440 / 8000) * 12000);
        BinaryPrimitives.WriteInt16LittleEndian(
            wav.AsSpan(44 + (index * sizeof(short))),
            sample);
    }

    return wav;
}

static string AddAuthorization(string request, string authorization)
{
    return request.Replace(
        "Content-Length:",
        $"Authorization: {authorization}\r\nContent-Length:",
        StringComparison.Ordinal);
}

static string GetDigestNonce(string response, string algorithm)
{
    foreach (string line in response.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
    {
        if (!line.StartsWith("WWW-Authenticate: Digest ", StringComparison.Ordinal) ||
            !line.Contains($"algorithm={algorithm}", StringComparison.Ordinal))
        {
            continue;
        }

        const string marker = "nonce=\"";
        int start = line.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "Digest challenge did not contain a nonce.");
        start += marker.Length;
        int end = line.IndexOf('"', start);
        Assert.True(end > start, "Digest challenge nonce was malformed.");
        return line[start..end];
    }

    throw new InvalidOperationException($"No {algorithm} Digest challenge was found.");
}

static string CreateDigestAuthorization(
    string userName,
    string realm,
    string password,
    string nonce,
    string method,
    string uri,
    string algorithm,
    bool includeAlgorithm)
{
    const string nonceCount = "00000001";
    const string cnonce = "0123456789abcdef";
    string ha1 = ComputeDigestHex($"{userName}:{realm}:{password}", algorithm);
    string ha2 = ComputeDigestHex($"{method}:{uri}", algorithm);
    string response = ComputeDigestHex(
        $"{ha1}:{nonce}:{nonceCount}:{cnonce}:auth:{ha2}",
        algorithm);
    string algorithmParameter = includeAlgorithm
        ? $", algorithm={algorithm}"
        : string.Empty;
    return $"Digest username=\"{userName}\", realm=\"{realm}\", nonce=\"{nonce}\", " +
        $"uri=\"{uri}\", response=\"{response}\"{algorithmParameter}, qop=auth, " +
        $"nc={nonceCount}, cnonce=\"{cnonce}\"";
}

static string ComputeDigestHex(string value, string algorithm)
{
    byte[] bytes = Encoding.UTF8.GetBytes(value);
    byte[] hash;
    if (algorithm == "SHA-256")
    {
        hash = SHA256.HashData(bytes);
    }
    else
    {
#pragma warning disable CA5351 // Test coverage for explicitly enabled legacy SIP Digest MD5.
        hash = MD5.HashData(bytes);
#pragma warning restore CA5351
    }

    return Convert.ToHexStringLower(hash);
}

static X509Certificate2 CreateServerCertificate()
{
    using X509Certificate2 ephemeral = CreateEphemeralServerCertificate();
    return X509CertificateLoader.LoadPkcs12(
        ephemeral.Export(X509ContentType.Pkcs12),
        password: null,
        OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet
            : X509KeyStorageFlags.EphemeralKeySet);
}

static X509Certificate2 CreateEphemeralServerCertificate()
{
    using RSA rsa = RSA.Create(2048);
    CertificateRequest request = new(
        "CN=localhost",
        rsa,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(
        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    OidCollection enhancedKeyUsage =
    [
        new("1.3.6.1.5.5.7.3.1")
    ];
    request.CertificateExtensions.Add(
        new X509EnhancedKeyUsageExtension(enhancedKeyUsage, true));
    SubjectAlternativeNameBuilder subjectAlternativeName = new();
    subjectAlternativeName.AddDnsName("localhost");
    request.CertificateExtensions.Add(subjectAlternativeName.Build());

    return request.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddMinutes(-5),
        DateTimeOffset.UtcNow.AddDays(1));
}

static byte[] Bytes(string value)
{
    return Encoding.ASCII.GetBytes(value);
}

static int CountOccurrences(ReadOnlySpan<byte> source, ReadOnlySpan<byte> value)
{
    int count = 0;
    while (source.IndexOf(value) is int index and >= 0)
    {
        count++;
        source = source[(index + value.Length)..];
    }

    return count;
}

internal static class Assert
{
    public static void True(bool condition, string? message = null)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message ?? "Expected condition to be true.");
        }
    }

    public static void False(bool condition, string? message = null)
    {
        True(!condition, message ?? "Expected condition to be false.");
    }

    public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
        }
    }

    public static void Equal(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException(
                $"Expected '{Encoding.ASCII.GetString(expected)}', got '{Encoding.ASCII.GetString(actual)}'.");
        }
    }

    public static void Contains(string expected, string actual)
    {
        if (!actual.Contains(expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Expected response to contain '{expected}'. Actual: '{actual}'");
        }
    }

    public static void DoesNotContain(string expected, string actual)
    {
        if (actual.Contains(expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Expected response not to contain '{expected}'. Actual: '{actual}'");
        }
    }
}

internal sealed class SegmentedSequence : ReadOnlySequenceSegment<byte>
{
    private SegmentedSequence(ReadOnlyMemory<byte> memory)
    {
        Memory = memory;
    }

    public static ReadOnlySequence<byte> Create(
        ReadOnlyMemory<byte> first,
        ReadOnlyMemory<byte> second,
        ReadOnlyMemory<byte> third)
    {
        SegmentedSequence start = new(first);
        SegmentedSequence middle = start.Append(second);
        SegmentedSequence end = middle.Append(third);
        return new ReadOnlySequence<byte>(start, 0, end, end.Memory.Length);
    }

    private SegmentedSequence Append(ReadOnlyMemory<byte> memory)
    {
        SegmentedSequence segment = new(memory)
        {
            RunningIndex = RunningIndex + Memory.Length
        };
        Next = segment;
        return segment;
    }
}

internal sealed class WaitingHandler : ISipRequestHandler
{
    public async ValueTask HandleAsync(
        SipRequestContext context,
        CancellationToken cancellationToken)
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }
}

internal sealed class AdjustableTimeProvider(DateTimeOffset utcNow) : TimeProvider
{
    private DateTimeOffset _utcNow = utcNow;

    public override DateTimeOffset GetUtcNow()
    {
        return _utcNow;
    }

    public void Advance(TimeSpan value)
    {
        _utcNow += value;
    }
}

internal sealed class UnsafeBindingHandler : ISipRequestHandler
{
    public ValueTask HandleAsync(
        SipRequestContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] injected = Encoding.ASCII.GetBytes(
            "<sip:alice@example.com>\r\nInjected: value");
        SipRegistrationBinding binding = new(injected, 60);
        if (!context.Response.WriteRegisterOk(context.Message, [binding]))
        {
            context.Response.WriteError(400);
        }

        return ValueTask.CompletedTask;
    }
}

internal sealed class CountingDialPlanProcessor(
    SipDialPlanResult result) : ISipDialPlanProcessor
{
    public int Calls { get; private set; }

    public ValueTask<SipDialPlanResult> ProcessAsync(
        SipInviteContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        return ValueTask.FromResult(result);
    }
}

internal sealed class UnsafeDialPlanProcessor : ISipDialPlanProcessor
{
    public ValueTask<SipDialPlanResult> ProcessAsync(
        SipInviteContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            SipDialPlanResult.Redirect(
                Encoding.ASCII.GetBytes(
                    "sips:agent@example.com\r\nInjected: value")));
    }
}

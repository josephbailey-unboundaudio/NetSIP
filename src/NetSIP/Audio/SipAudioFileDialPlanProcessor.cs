using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetSIP.Message;
using NetSIP.Request;
using NetSIP.Common;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace NetSIP.Audio
{

    /// <summary>
    /// Routes one extension to a validated WAV file streamed as PCMU RTP and delegates all
    /// other destinations to another dialplan processor.
    /// </summary>
    public sealed class SipAudioFileDialPlanProcessor : ISipDialPlanProcessor, IAsyncDisposable
    {
        private const int RtpHeaderBytes = 12;
        private const int SamplesPerPacket = 160;
        private const int SampleRate = 8000;
        private const byte PcmuPayloadType = 0;

        private readonly ISipDialPlanProcessor _inner;
        private readonly SipAudioFilePlaybackOptions _options;
        private readonly ILogger _logger;
        private readonly byte[] _extension;
        private readonly byte[] _contact;
        private readonly byte[] _pcmuAudio;
        private readonly SemaphoreSlim _sessionSlots;
        // Scheduling and disposal share this gate so no session can outlive the disposal snapshot.
        private readonly Lock _lifecycleGate = new();
        private readonly CancellationTokenSource _lifetime = new();
        private readonly ConcurrentDictionary<long, PlaybackSession> _sessions = new();
        private long _nextSessionId;
        private int _disposed;

        /// <summary>Loads the configured WAV file and initializes the playback route.</summary>
        /// <param name="inner">The dialplan used for destinations other than the playback extension.</param>
        /// <param name="options">Playback, media-address, and resource-limit configuration.</param>
        /// <param name="logger">An optional logger for RTP transport failures.</param>
        public SipAudioFileDialPlanProcessor(
            ISipDialPlanProcessor inner,
            SipAudioFilePlaybackOptions options,
            ILogger<SipAudioFileDialPlanProcessor>? logger = null)
        {
            ArgumentNullException.ThrowIfNull(inner);
            ArgumentNullException.ThrowIfNull(options);
            options.Validate();

            _inner = inner;
            _options = options;
            _logger = logger ?? NullLogger<SipAudioFileDialPlanProcessor>.Instance;
            _extension = Encoding.ASCII.GetBytes(options.Extension);
            _contact = Encoding.ASCII.GetBytes(options.Contact);
            _pcmuAudio = LoadAndTranscodeWav(options);
            _sessionSlots = new SemaphoreSlim(options.MaxConcurrentSessions);
        }

        /// <inheritdoc />
        public ValueTask<SipDialPlanResult> ProcessAsync(
            SipInviteContext context,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SipMessageView request = context.Request;
            if (!SipUri.GetUser(request.RequestUri).SequenceEqual(_extension))
            {
                return _inner.ProcessAsync(context, cancellationToken);
            }

            if (!TryGetMediaTarget(
                    request,
                    context.RemoteEndPoint,
                    _options.RequireMediaAddressMatchSignalingPeer,
                    out IPEndPoint remoteMedia))
            {
                return ValueTask.FromResult(
                    SipDialPlanResult.Reject(488, "Not Acceptable Here"u8.ToArray()));
            }

            if (remoteMedia.AddressFamily != _options.BindAddress.AddressFamily)
            {
                return ValueTask.FromResult(
                    SipDialPlanResult.Reject(488, "Not Acceptable Here"u8.ToArray()));
            }

            lock (_lifecycleGate)
            {
                if (_disposed != 0)
                {
                    return ValueTask.FromResult(
                        SipDialPlanResult.Reject(503, "Service Unavailable"u8.ToArray()));
                }

                if (!_sessionSlots.Wait(0, cancellationToken))
                {
                    return ValueTask.FromResult(
                        SipDialPlanResult.Reject(486, "Busy Here"u8.ToArray()));
                }

                Socket? socket = null;
                bool scheduled = false;
                try
                {
                    socket = new Socket(
                        _options.BindAddress.AddressFamily,
                        SocketType.Dgram,
                        ProtocolType.Udp);
                    socket.Bind(new IPEndPoint(_options.BindAddress, 0));
                    int localPort = ((IPEndPoint)socket.LocalEndPoint!).Port;
                    byte[] sdp = CreateSdpAnswer(_options.AdvertisedAddress, localPort);
                    SchedulePlayback(socket, remoteMedia);
                    scheduled = true;
                    socket = null;
                    return ValueTask.FromResult(
                        SipDialPlanResult.Answer(
                            _contact,
                            sdp,
                            "application/sdp"u8.ToArray()));
                }
                catch (SocketException exception)
                {
                    SipAudioPlaybackLog.SessionSetupFailed(_logger, remoteMedia, exception);
                    return ValueTask.FromResult(
                        SipDialPlanResult.Reject(503, "Service Unavailable"u8.ToArray()));
                }
                finally
                {
                    socket?.Dispose();
                    if (!scheduled)
                    {
                        _sessionSlots.Release();
                    }
                }
            }
        }

        /// <summary>Cancels active playback and waits for all RTP sessions to release their sockets.</summary>
        public async ValueTask DisposeAsync()
        {
            Task[] sessions;
            lock (_lifecycleGate)
            {
                if (_disposed != 0)
                {
                    return;
                }

                _disposed = 1;
                _lifetime.Cancel();
                sessions = [.. _sessions.Values.Select(static session => session.Task)];
            }

            if (sessions.Length != 0)
            {
                await Task.WhenAll(sessions).ConfigureAwait(false);
            }

            _sessionSlots.Dispose();
            _lifetime.Dispose();
        }

        private void SchedulePlayback(Socket socket, IPEndPoint remoteMedia)
        {
            long sessionId = Interlocked.Increment(ref _nextSessionId);
            PlaybackSession session = new();
            if (!_sessions.TryAdd(sessionId, session))
            {
                throw new InvalidOperationException("Unable to track a unique RTP playback session.");
            }

            session.Task = RunPlaybackAsync(
                sessionId,
                socket,
                remoteMedia,
                _lifetime.Token);
        }

        private async Task RunPlaybackAsync(
            long sessionId,
            Socket socket,
            IPEndPoint remoteMedia,
            CancellationToken cancellationToken)
        {
            try
            {
                try
                {
                    if (_options.StartDelay > TimeSpan.Zero)
                    {
                        await Task.Delay(_options.StartDelay, cancellationToken).ConfigureAwait(false);
                    }

                    ushort sequence = unchecked((ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1));
                    uint timestamp = unchecked((uint)RandomNumberGenerator.GetInt32(int.MaxValue));
                    uint synchronizationSource = unchecked((uint)RandomNumberGenerator.GetInt32(int.MaxValue));
                    byte[] packet = new byte[RtpHeaderBytes + SamplesPerPacket];
                    long started = Stopwatch.GetTimestamp();
                    int packetIndex = 0;
                    for (int offset = 0; offset < _pcmuAudio.Length; offset += SamplesPerPacket)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        int sampleCount = Math.Min(SamplesPerPacket, _pcmuAudio.Length - offset);
                        WriteRtpHeader(
                            packet,
                            sequence++,
                            timestamp,
                            synchronizationSource,
                            marker: offset == 0);
                        timestamp += (uint)sampleCount;
                        _pcmuAudio.AsSpan(offset, sampleCount).CopyTo(packet.AsSpan(RtpHeaderBytes));
                        _ = await socket.SendToAsync(
                            packet.AsMemory(0, RtpHeaderBytes + sampleCount),
                            SocketFlags.None,
                            remoteMedia,
                            cancellationToken).ConfigureAwait(false);

                        packetIndex++;
                        // Pace against the original start time so individual delay error does not accumulate.
                        TimeSpan remaining = TimeSpan.FromMilliseconds(packetIndex * 20) -
                            Stopwatch.GetElapsedTime(started);
                        if (remaining > TimeSpan.Zero && offset + sampleCount < _pcmuAudio.Length)
                        {
                            await Task.Delay(remaining, cancellationToken).ConfigureAwait(false);
                        }
                    }

                    SipAudioPlaybackLog.SessionCompleted(
                        _logger,
                        sessionId,
                        remoteMedia,
                        _pcmuAudio.Length);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    SipAudioPlaybackLog.SessionCanceled(_logger, sessionId, remoteMedia);
                }
                catch (SocketException exception)
                {
                    SipAudioPlaybackLog.SessionTransportFailed(
                        _logger,
                        sessionId,
                        remoteMedia,
                        exception);
                }
                finally
                {
                    _sessionSlots.Release();
                }
            }
            finally
            {
                socket.Dispose();
                _sessions.TryRemove(sessionId, out PlaybackSession? _);
            }
        }

        private static void WriteRtpHeader(
            Span<byte> packet,
            ushort sequence,
            uint timestamp,
            uint synchronizationSource,
            bool marker)
        {
            packet[0] = 0x80;
            packet[1] = (byte)(PcmuPayloadType | (marker ? 0x80 : 0));
            BinaryPrimitives.WriteUInt16BigEndian(packet[2..], sequence);
            BinaryPrimitives.WriteUInt32BigEndian(packet[4..], timestamp);
            BinaryPrimitives.WriteUInt32BigEndian(packet[8..], synchronizationSource);
        }

        private static byte[] CreateSdpAnswer(IPAddress address, int port)
        {
            string addressType = address.AddressFamily == AddressFamily.InterNetwork
                ? "IP4"
                : "IP6";
            long sessionId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string invariantSessionId = sessionId.ToString(CultureInfo.InvariantCulture);
            string invariantPort = port.ToString(CultureInfo.InvariantCulture);
            string sdp =
                "v=0\r\n" +
                $"o=NetSIP {invariantSessionId} {invariantSessionId} IN {addressType} {address}\r\n" +
                "s=NetSIP audio playback\r\n" +
                $"c=IN {addressType} {address}\r\n" +
                "t=0 0\r\n" +
                $"m=audio {invariantPort} RTP/AVP 0\r\n" +
                "a=rtpmap:0 PCMU/8000\r\n" +
                "a=sendonly\r\n";
            return Encoding.ASCII.GetBytes(sdp);
        }

        private static bool TryGetMediaTarget(
            SipMessageView request,
            EndPoint? remoteEndPoint,
            bool requireSignalingPeer,
            out IPEndPoint mediaTarget)
        {
            mediaTarget = null!;
            if (!HasSdpContentType(request))
            {
                return false;
            }

            ReadOnlySpan<byte> body = request.Body;
            IPAddress? sessionAddress = null;
            IPAddress? mediaAddress = null;
            int mediaPort = 0;
            bool inMediaSection = false;
            bool inSelectedAudioMedia = false;
            bool pcmuOffered = false;
            int mediaSectionCount = 0;
            SdpDirection sessionDirection = SdpDirection.SendReceive;
            SdpDirection? mediaDirection = null;
            bool sessionDirectionSpecified = false;
            bool mediaDirectionSpecified = false;
            bool invalidDirection = false;
            while (!body.IsEmpty)
            {
                int lineEnd = body.IndexOf((byte)'\n');
                ReadOnlySpan<byte> line = lineEnd < 0 ? body : body[..lineEnd];
                body = lineEnd < 0 ? [] : body[(lineEnd + 1)..];
                if (!line.IsEmpty && line[^1] == (byte)'\r')
                {
                    line = line[..^1];
                }

                if (line.StartsWith("m="u8))
                {
                    // Select the first audio media section that explicitly offers static payload 0.
                    inMediaSection = true;
                    mediaSectionCount++;
                    bool parsed = TryParseAudioMedia(
                        line[2..],
                        out int parsedPort,
                        out bool hasPcmu);
                    inSelectedAudioMedia = mediaPort == 0 && parsed && hasPcmu;
                    if (inSelectedAudioMedia)
                    {
                        mediaPort = parsedPort;
                        pcmuOffered = true;
                    }

                    continue;
                }

                if (TryParseDirection(line, out SdpDirection parsedDirection))
                {
                    if (inMediaSection)
                    {
                        invalidDirection |= mediaDirectionSpecified;
                        mediaDirection = parsedDirection;
                        mediaDirectionSpecified = true;
                    }
                    else
                    {
                        invalidDirection |= sessionDirectionSpecified;
                        sessionDirection = parsedDirection;
                        sessionDirectionSpecified = true;
                    }

                    continue;
                }

                if (line.StartsWith("c="u8) &&
                    TryParseConnectionAddress(line[2..], out IPAddress? parsedAddress))
                {
                    // A media-level connection overrides the session-level address for that m-line.
                    if (inSelectedAudioMedia)
                    {
                        mediaAddress = parsedAddress;
                    }
                    else if (!inMediaSection)
                    {
                        sessionAddress = parsedAddress;
                    }
                }
            }

            IPAddress? address = mediaAddress ?? sessionAddress;
            if (mediaPort == 0 ||
                !pcmuOffered ||
                mediaSectionCount != 1 ||
                invalidDirection ||
                (mediaDirection ?? sessionDirection) is
                    not (SdpDirection.SendReceive or SdpDirection.ReceiveOnly) ||
                address is null ||
                !SipAudioFilePlaybackOptions.IsUnicast(address))
            {
                return false;
            }

            if (requireSignalingPeer &&
                (remoteEndPoint is not IPEndPoint signalingPeer ||
                    !AddressesEqual(address, signalingPeer.Address)))
            {
                return false;
            }

            mediaTarget = new IPEndPoint(address, mediaPort);
            return true;
        }

        private static bool TryParseDirection(
            ReadOnlySpan<byte> line,
            out SdpDirection direction)
        {
            direction = SdpDirection.SendReceive;
            if (AsciiUtilities.EqualsIgnoreCase(line, "a=sendrecv"u8))
            {
                return true;
            }

            if (AsciiUtilities.EqualsIgnoreCase(line, "a=sendonly"u8))
            {
                direction = SdpDirection.SendOnly;
                return true;
            }

            if (AsciiUtilities.EqualsIgnoreCase(line, "a=recvonly"u8))
            {
                direction = SdpDirection.ReceiveOnly;
                return true;
            }

            if (AsciiUtilities.EqualsIgnoreCase(line, "a=inactive"u8))
            {
                direction = SdpDirection.Inactive;
                return true;
            }

            return false;
        }

        private static bool HasSdpContentType(SipMessageView request)
        {
            int count = 0;
            SipHeaderEnumerator headers = request.GetHeaders();
            while (headers.MoveNext())
            {
                SipHeaderView header = headers.Current;
                if (!AsciiUtilities.EqualsIgnoreCase(header.Name, "Content-Type"u8) &&
                    !AsciiUtilities.EqualsIgnoreCase(header.Name, "c"u8))
                {
                    continue;
                }

                count++;
                ReadOnlySpan<byte> value = header.Value;
                int parameters = value.IndexOf((byte)';');
                if (parameters >= 0)
                {
                    value = AsciiUtilities.TrimOptionalWhitespace(value[..parameters]);
                }

                if (!AsciiUtilities.EqualsIgnoreCase(value, "application/sdp"u8))
                {
                    return false;
                }
            }

            return count == 1 && !request.Body.IsEmpty;
        }

        private static bool TryParseAudioMedia(
            ReadOnlySpan<byte> value,
            out int port,
            out bool hasPcmu)
        {
            Span<Range> tokens = stackalloc Range[64];
            int tokenCount = SplitOnWhitespace(value, tokens);
            port = 0;
            hasPcmu = false;
            if (tokenCount < 4 ||
                !AsciiUtilities.EqualsIgnoreCase(value[tokens[0]], "audio"u8) ||
                !TryParsePort(value[tokens[1]], out port) ||
                !AsciiUtilities.EqualsIgnoreCase(value[tokens[2]], "RTP/AVP"u8))
            {
                return false;
            }

            for (int index = 3; index < tokenCount; index++)
            {
                if (value[tokens[index]].SequenceEqual("0"u8))
                {
                    hasPcmu = true;
                    break;
                }
            }

            return true;
        }

        private static bool TryParseConnectionAddress(
            ReadOnlySpan<byte> value,
            out IPAddress? address)
        {
            Span<Range> tokens = stackalloc Range[3];
            int tokenCount = SplitOnWhitespace(value, tokens);
            address = null;
            if (tokenCount != 3 ||
                !AsciiUtilities.EqualsIgnoreCase(value[tokens[0]], "IN"u8))
            {
                return false;
            }

            AddressFamily family;
            if (AsciiUtilities.EqualsIgnoreCase(value[tokens[1]], "IP4"u8))
            {
                family = AddressFamily.InterNetwork;
            }
            else if (AsciiUtilities.EqualsIgnoreCase(value[tokens[1]], "IP6"u8))
            {
                family = AddressFamily.InterNetworkV6;
            }
            else
            {
                return false;
            }

            if (!IPAddress.TryParse(Encoding.ASCII.GetString(value[tokens[2]]), out address) ||
                address.AddressFamily != family)
            {
                address = null;
                return false;
            }

            return true;
        }

        private static int SplitOnWhitespace(ReadOnlySpan<byte> value, Span<Range> tokens)
        {
            int count = 0;
            int index = 0;
            while (index < value.Length)
            {
                while (index < value.Length && AsciiUtilities.IsOptionalWhitespace(value[index]))
                {
                    index++;
                }

                if (index == value.Length)
                {
                    break;
                }

                int start = index;
                while (index < value.Length && !AsciiUtilities.IsOptionalWhitespace(value[index]))
                {
                    index++;
                }

                if (count == tokens.Length)
                {
                    return -1;
                }

                tokens[count++] = start..index;
            }

            return count;
        }

        private static bool TryParsePort(ReadOnlySpan<byte> value, out int port)
        {
            int slash = value.IndexOf((byte)'/');
            if (slash >= 0)
            {
                value = value[..slash];
            }

            port = 0;
            if (value.IsEmpty)
            {
                return false;
            }

            foreach (byte current in value)
            {
                if (current is < (byte)'0' or > (byte)'9' ||
                    port > (65535 - (current - '0')) / 10)
                {
                    port = 0;
                    return false;
                }

                port = (port * 10) + current - '0';
            }

            return port > 0;
        }

        private static bool AddressesEqual(IPAddress left, IPAddress right)
        {
            if (left.IsIPv4MappedToIPv6)
            {
                left = left.MapToIPv4();
            }

            if (right.IsIPv4MappedToIPv6)
            {
                right = right.MapToIPv4();
            }

            return left.Equals(right);
        }

        private static byte[] LoadAndTranscodeWav(SipAudioFilePlaybackOptions options)
        {
            string path = Path.GetFullPath(options.AudioFilePath);
            FileInfo file = new(path);
            if (!file.Exists || file.Length > options.MaxAudioFileBytes)
            {
                throw new ArgumentException(
                    "The playback WAV file does not exist or exceeds MaxAudioFileBytes.",
                    nameof(options));
            }

            byte[] wav = File.ReadAllBytes(path);
            return WavPcmuTranscoder.Transcode(
                wav,
                checked((int)Math.Floor(options.MaxPlaybackDuration.TotalSeconds * SampleRate)));
        }

        private sealed class PlaybackSession
        {
            // Assigned while the lifecycle gate is held before disposal can take its task snapshot.
            public Task Task { get; set; } = Task.CompletedTask;
        }

        private enum SdpDirection
        {
            SendReceive,
            SendOnly,
            ReceiveOnly,
            Inactive
        }
    }

}

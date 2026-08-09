using System.Buffers.Binary;

namespace NetSIP;

internal static class WavPcmuTranscoder
{
    private const ushort PcmFormat = 1;
    private const ushort MuLawFormat = 7;
    private const int OutputSampleRate = 8000;

    public static byte[] Transcode(ReadOnlySpan<byte> wav, int maxOutputSamples)
    {
        if (wav.Length < 12 ||
            !wav[..4].SequenceEqual("RIFF"u8) ||
            !wav.Slice(8, 4).SequenceEqual("WAVE"u8))
        {
            throw new InvalidDataException("Playback audio must be a RIFF WAVE file.");
        }

        ReadOnlySpan<byte> format = default;
        ReadOnlySpan<byte> data = default;
        int offset = 12;
        while (offset <= wav.Length - 8)
        {
            ReadOnlySpan<byte> chunkId = wav.Slice(offset, 4);
            uint chunkLength = BinaryPrimitives.ReadUInt32LittleEndian(wav.Slice(offset + 4, 4));
            int contentOffset = offset + 8;
            if (chunkLength > int.MaxValue ||
                contentOffset > wav.Length - (int)chunkLength)
            {
                throw new InvalidDataException("The WAV file contains a truncated chunk.");
            }

            ReadOnlySpan<byte> content = wav.Slice(contentOffset, (int)chunkLength);
            if (chunkId.SequenceEqual("fmt "u8) && format.IsEmpty)
            {
                format = content;
            }
            else if (chunkId.SequenceEqual("data"u8) && data.IsEmpty)
            {
                data = content;
            }

            // RIFF chunks are word-aligned; the padding byte is not part of chunkLength.
            offset = checked(contentOffset + (int)chunkLength + ((int)chunkLength & 1));
        }

        if (format.Length < 16 || data.IsEmpty)
        {
            throw new InvalidDataException("The WAV file requires fmt and non-empty data chunks.");
        }

        ushort encoding = BinaryPrimitives.ReadUInt16LittleEndian(format);
        ushort channels = BinaryPrimitives.ReadUInt16LittleEndian(format[2..]);
        int sampleRate = BinaryPrimitives.ReadInt32LittleEndian(format[4..]);
        ushort blockAlign = BinaryPrimitives.ReadUInt16LittleEndian(format[12..]);
        ushort bitsPerSample = BinaryPrimitives.ReadUInt16LittleEndian(format[14..]);
        if (encoding == MuLawFormat)
        {
            ValidateMuLawFormat(channels, sampleRate, bitsPerSample, blockAlign);
            return data.Length <= maxOutputSamples
                ? data.ToArray()
                : throw new InvalidDataException("The WAV file exceeds MaxPlaybackDuration.");
        }

        if (encoding != PcmFormat ||
            channels is < 1 or > 2 ||
            sampleRate is < 8000 or > 48000 ||
            bitsPerSample is not (8 or 16) ||
            blockAlign != channels * (bitsPerSample / 8))
        {
            throw new InvalidDataException(
                "PCM WAV input must be mono or stereo, 8-48 kHz, and 8 or 16 bits per sample.");
        }

        int frameCount = data.Length / blockAlign;
        if (data.Length % blockAlign != 0)
        {
            throw new InvalidDataException("The PCM data chunk does not contain complete sample frames.");
        }

        int outputSamples = checked((int)Math.Ceiling(
            frameCount * (double)OutputSampleRate / sampleRate));
        if (outputSamples == 0 || outputSamples > maxOutputSamples)
        {
            throw new InvalidDataException("The WAV file is empty or exceeds MaxPlaybackDuration.");
        }

        byte[] output = new byte[outputSamples];
        for (int outputIndex = 0; outputIndex < output.Length; outputIndex++)
        {
            // Nearest-neighbor resampling is deterministic and sufficient for narrowband prompts.
            int sourceFrame = Math.Min(
                frameCount - 1,
                (int)((long)outputIndex * sampleRate / OutputSampleRate));
            int frameOffset = sourceFrame * blockAlign;
            int mixed = 0;
            for (int channel = 0; channel < channels; channel++)
            {
                int sampleOffset = frameOffset + (channel * (bitsPerSample / 8));
                mixed += bitsPerSample == 16
                    ? BinaryPrimitives.ReadInt16LittleEndian(data[sampleOffset..])
                    : (data[sampleOffset] - 128) << 8;
            }

            output[outputIndex] = LinearPcmToMuLaw((short)(mixed / channels));
        }

        return output;
    }

    private static void ValidateMuLawFormat(
        ushort channels,
        int sampleRate,
        ushort bitsPerSample,
        ushort blockAlign)
    {
        if (channels != 1 ||
            sampleRate != OutputSampleRate ||
            bitsPerSample != 8 ||
            blockAlign != 1)
        {
            throw new InvalidDataException(
                "G.711 mu-law WAV input must be mono, 8 kHz, and 8 bits per sample.");
        }
    }

    private static byte LinearPcmToMuLaw(short value)
    {
        const int bias = 0x84;
        const int clip = 32635;
        int sample = value;
        int sign = sample < 0 ? 0x80 : 0;
        if (sample < 0)
        {
            sample = -sample;
        }

        sample = Math.Min(sample, clip) + bias;
        int exponent = 7;
        for (int mask = 0x4000; (sample & mask) == 0 && exponent > 0; mask >>= 1)
        {
            exponent--;
        }

        int mantissa = (sample >> (exponent + 3)) & 0x0f;
        return (byte)~(sign | (exponent << 4) | mantissa);
    }
}

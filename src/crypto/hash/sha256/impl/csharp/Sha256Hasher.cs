using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Abc.Cryptography;

public enum Sha256Status
{
    Success,
    MessageTooLong,
    DestinationTooShort,
}

/// <summary>Portable, byte-oriented SHA-256. Serialize calls on one context.</summary>
public sealed class Sha256Hasher
{
    public const int DigestSize = 32;
    public const int BlockSize = 64;
    public const ulong MaxMessageBytes = (1UL << 61) - 1;

    // FIPS 180-4 §§ 4.2.2, 5.3.3.
    private static ReadOnlySpan<uint> InitialState =>
    [
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    ];

    private static ReadOnlySpan<uint> RoundConstants =>
    [
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    ];

    private readonly uint[] state = InitialState.ToArray();
    private readonly byte[] pending = new byte[BlockSize];
    private int used;
    private ulong length;

    /// <summary>Add bytes without retaining the source span. Rejection preserves the context.</summary>
    public Sha256Status Update(ReadOnlySpan<byte> input)
    {
        if ((ulong)input.Length > MaxMessageBytes - length)
            return Sha256Status.MessageTooLong;
        if (input.IsEmpty)
            return Sha256Status.Success;
        length += (ulong)input.Length;

        if (used != 0)
        {
            int count = Math.Min(input.Length, BlockSize - used);
            input[..count].CopyTo(pending.AsSpan(used));
            used += count;
            if (used < BlockSize)
                return Sha256Status.Success;
            Compress(state, pending);
            input = input[count..];
        }
        while (input.Length >= BlockSize)
        {
            Compress(state, input[..BlockSize]);
            input = input[BlockSize..];
        }
        input.CopyTo(pending);
        used = input.Length;
        return Sha256Status.Success;
    }

    /// <summary>Write a digest snapshot without consuming or altering the context.</summary>
    public Sha256Status Digest(Span<byte> destination)
    {
        if (destination.Length < DigestSize)
            return Sha256Status.DestinationTooShort;

        Span<uint> snapshot = stackalloc uint[8];
        state.AsSpan().CopyTo(snapshot);
        Span<byte> finalBlocks = stackalloc byte[2 * BlockSize];
        finalBlocks.Clear();
        pending.AsSpan(0, used).CopyTo(finalBlocks);
        finalBlocks[used] = 0x80;
        int end = used < BlockSize - sizeof(ulong) ? BlockSize : 2 * BlockSize;
        BinaryPrimitives.WriteUInt64BigEndian(finalBlocks[(end - sizeof(ulong))..], length * 8UL);
        for (int offset = 0; offset < end; offset += BlockSize)
            Compress(snapshot, finalBlocks.Slice(offset, BlockSize));
        for (int i = 0; i < snapshot.Length; ++i)
            BinaryPrimitives.WriteUInt32BigEndian(destination[(4 * i)..], snapshot[i]);
        return Sha256Status.Success;
    }

    /// <summary>Start a new empty message.</summary>
    public void Reset()
    {
        InitialState.CopyTo(state);
        used = 0;
        length = 0;
    }

    /// <summary>Hash a byte string and write the first 32 bytes of the destination.</summary>
    public static Sha256Status Hash(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        if (destination.Length < DigestSize)
            return Sha256Status.DestinationTooShort;
        var hasher = new Sha256Hasher();
        Sha256Status status = hasher.Update(input);
        return status == Sha256Status.Success ? hasher.Digest(destination) : status;
    }

    // FIPS 180-4 §§ 5.2.1, 6.2.2. SHA-256 additions wrap modulo 2^32.
    private static void Compress(Span<uint> state, ReadOnlySpan<byte> block)
    {
        Span<uint> words = stackalloc uint[64];
        ReadOnlySpan<uint> constants = RoundConstants;
        unchecked
        {
            for (int i = 0; i < 16; ++i)
                words[i] = BinaryPrimitives.ReadUInt32BigEndian(block[(4 * i)..]);
            for (int i = 16; i < words.Length; ++i)
            {
                uint earlier = words[i - 15], recent = words[i - 2];
                uint low = BitOperations.RotateRight(earlier, 7) ^ BitOperations.RotateRight(earlier, 18) ^ (earlier >> 3);
                uint high = BitOperations.RotateRight(recent, 17) ^ BitOperations.RotateRight(recent, 19) ^ (recent >> 10);
                words[i] = words[i - 16] + low + words[i - 7] + high;
            }

            uint a = state[0], b = state[1], c = state[2], d = state[3];
            uint e = state[4], f = state[5], g = state[6], h = state[7];
            for (int i = 0; i < words.Length; ++i)
            {
                uint upper = BitOperations.RotateRight(e, 6) ^ BitOperations.RotateRight(e, 11) ^ BitOperations.RotateRight(e, 25);
                uint choose = (e & f) ^ (~e & g);
                uint first = h + upper + choose + constants[i] + words[i];
                uint lower = BitOperations.RotateRight(a, 2) ^ BitOperations.RotateRight(a, 13) ^ BitOperations.RotateRight(a, 22);
                uint majority = (a & b) ^ (a & c) ^ (b & c);
                uint second = lower + majority;
                h = g;
                g = f;
                f = e;
                e = d + first;
                d = c;
                c = b;
                b = a;
                a = first + second;
            }
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }
    }
}

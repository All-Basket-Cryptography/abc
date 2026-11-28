using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Abc.Cryptography;

public enum Sha512Status
{
    Success,
    MessageTooLong,
    DestinationTooShort,
}

/// <summary>Portable, byte-oriented SHA-512. Serialize calls on one context.</summary>
public sealed class Sha512Hasher
{
    public const int DigestSize = 64;
    public const int BlockSize = 128;
    public static readonly UInt128 MaxMessageBytes = UInt128.MaxValue / 8;

    // FIPS 180-4 §§ 4.2.3 and 5.3.5.
    private static ReadOnlySpan<ulong> InitialState =>
    [
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
    ];

    private static ReadOnlySpan<ulong> RoundConstants =>
    [
        0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
        0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
        0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
        0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
        0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
        0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
        0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
        0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
        0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
        0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
        0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
        0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
        0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
        0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
        0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
        0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
        0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
        0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
    ];

    private readonly ulong[] state = InitialState.ToArray();
    private readonly byte[] pending = new byte[BlockSize];
    private int used;
    private UInt128 length;

    /// <summary>Add bytes without retaining the source span. Rejection preserves the context.</summary>
    public Sha512Status Update(ReadOnlySpan<byte> input)
    {
        if ((UInt128)input.Length > MaxMessageBytes - length)
            return Sha512Status.MessageTooLong;
        if (input.IsEmpty)
            return Sha512Status.Success;
        length += (UInt128)input.Length;

        if (used != 0)
        {
            int count = Math.Min(input.Length, BlockSize - used);
            input[..count].CopyTo(pending.AsSpan(used));
            used += count;
            if (used < BlockSize)
                return Sha512Status.Success;
            Compress(state, pending);
            input = input[count..];
        }
        input = CompressBlocks(state, input);
        input.CopyTo(pending);
        used = input.Length;
        return Sha512Status.Success;
    }

    /// <summary>Write a digest snapshot without consuming or altering the context.</summary>
    public Sha512Status Digest(Span<byte> destination)
    {
        if (destination.Length < DigestSize)
            return Sha512Status.DestinationTooShort;

        Span<ulong> snapshot = stackalloc ulong[8];
        state.AsSpan().CopyTo(snapshot);
        Finish(snapshot, pending.AsSpan(0, used), length, destination);
        return Sha512Status.Success;
    }

    /// <summary>Start a new empty message.</summary>
    public void Reset()
    {
        InitialState.CopyTo(state);
        used = 0;
        length = 0;
    }

    /// <summary>Hash input and write the first 64 bytes of the destination. Spans may overlap.</summary>
    public static Sha512Status Hash(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        if (destination.Length < DigestSize)
            return Sha512Status.DestinationTooShort;
        Span<ulong> state = stackalloc ulong[8];
        InitialState.CopyTo(state);
        ReadOnlySpan<byte> tail = CompressBlocks(state, input);
        Finish(state, tail, (UInt128)input.Length, destination);
        return Sha512Status.Success;
    }

    private static ReadOnlySpan<byte> CompressBlocks(scoped Span<ulong> state, ReadOnlySpan<byte> input)
    {
        while (input.Length >= BlockSize)
        {
            Compress(state, input[..BlockSize]);
            input = input[BlockSize..];
        }
        return input;
    }

    private static void Finish(Span<ulong> state, ReadOnlySpan<byte> tail, UInt128 length, Span<byte> destination)
    {
        Span<byte> finalBlocks = stackalloc byte[2 * BlockSize];
        finalBlocks.Clear();
        tail.CopyTo(finalBlocks);
        finalBlocks[tail.Length] = 0x80;
        int end = tail.Length < BlockSize - 16 ? BlockSize : 2 * BlockSize;
        BinaryPrimitives.WriteUInt128BigEndian(finalBlocks[(end - 16)..], length << 3);
        CompressBlocks(state, finalBlocks[..end]);
        for (int i = 0; i < state.Length; ++i)
            BinaryPrimitives.WriteUInt64BigEndian(destination[(8 * i)..], state[i]);
    }

    // FIPS 180-4 §§ 5.2.2 and 6.4.2. SHA-512 additions wrap modulo 2^64.
    private static void Compress(Span<ulong> state, ReadOnlySpan<byte> block)
    {
        Span<ulong> words = stackalloc ulong[80];
        ReadOnlySpan<ulong> constants = RoundConstants;
        unchecked
        {
            for (int i = 0; i < 16; ++i)
                words[i] = BinaryPrimitives.ReadUInt64BigEndian(block[(8 * i)..]);
            for (int i = 16; i < words.Length; ++i)
            {
                ulong earlier = words[i - 15], recent = words[i - 2];
                ulong low = BitOperations.RotateRight(earlier, 1) ^ BitOperations.RotateRight(earlier, 8) ^ (earlier >> 7);
                ulong high = BitOperations.RotateRight(recent, 19) ^ BitOperations.RotateRight(recent, 61) ^ (recent >> 6);
                words[i] = words[i - 16] + low + words[i - 7] + high;
            }

            ulong a = state[0], b = state[1], c = state[2], d = state[3];
            ulong e = state[4], f = state[5], g = state[6], h = state[7];
            for (int i = 0; i < words.Length; ++i)
            {
                ulong upper = BitOperations.RotateRight(e, 14) ^ BitOperations.RotateRight(e, 18) ^ BitOperations.RotateRight(e, 41);
                ulong choose = (e & f) ^ (~e & g);
                ulong first = h + upper + choose + constants[i] + words[i];
                ulong lower = BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
                ulong majority = (a & b) ^ (a & c) ^ (b & c);
                ulong second = lower + majority;
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

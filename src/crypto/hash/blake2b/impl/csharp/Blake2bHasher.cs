using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace Abc.Cryptography;

public enum Blake2bStatus
{
    Success,
    InvalidDigestSize,
    MessageTooLong,
}

/// <summary>Sequential unkeyed BLAKE2b. Serialize operations on a shared context.</summary>
public sealed class Blake2bHasher
{
    public const int BlockSize = 128;
    public const int MaxDigestSize = 64;

    private static ReadOnlySpan<ulong> InitialState =>
    [
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
    ];

    private static ReadOnlySpan<byte> Sigma =>
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ];

    private readonly ulong[] state;
    private readonly byte[] pending;
    private UInt128 compressedBytes;
    private int used;

    public int DigestSize { get; }

    public Blake2bHasher(int digestSize = MaxDigestSize)
    {
        if (digestSize < 1 || digestSize > MaxDigestSize)
            throw new ArgumentOutOfRangeException(nameof(digestSize));
        DigestSize = digestSize;
        state = new ulong[8];
        pending = new byte[BlockSize];
        Reset();
    }

    /// <summary>Clear the stream while retaining its configured digest size.</summary>
    public void Reset()
    {
        Initialize(state, DigestSize);
        compressedBytes = 0;
        used = 0;
    }

    /// <summary>Read the input without retaining its storage. Overflow leaves the stream unchanged.</summary>
    public Blake2bStatus Update(ReadOnlySpan<byte> input)
    {
        UInt128 added = (UInt128)used + (UInt128)input.Length;
        if (added > UInt128.MaxValue - compressedBytes)
            return Blake2bStatus.MessageTooLong;

        int available = BlockSize - used;
        if (input.Length <= available)
        {
            input.CopyTo(pending.AsSpan(used));
            used += input.Length;
            return Blake2bStatus.Success;
        }
        if (used != 0)
        {
            input[..available].CopyTo(pending.AsSpan(used));
            compressedBytes += BlockSize;
            Compress(state, pending, compressedBytes, final: false);
            input = input[available..];
        }
        int processed = CompressNonFinal(state, input, ref compressedBytes);
        input[processed..].CopyTo(pending);
        used = input.Length - processed;
        return Blake2bStatus.Success;
    }

    /// <summary>Snapshot the digest into a destination of exactly <see cref="DigestSize"/> bytes.</summary>
    public Blake2bStatus Digest(Span<byte> destination)
    {
        if (destination.Length != DigestSize)
            return Blake2bStatus.InvalidDigestSize;
        Span<ulong> snapshot = stackalloc ulong[8];
        state.AsSpan().CopyTo(snapshot);
        Finish(snapshot, pending.AsSpan(0, used), compressedBytes + (UInt128)used, destination);
        return Blake2bStatus.Success;
    }

    /// <summary>Hash using the destination length as the digest size. The spans may overlap.</summary>
    public static Blake2bStatus Hash(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        if (destination.IsEmpty || destination.Length > MaxDigestSize)
            return Blake2bStatus.InvalidDigestSize;
        Span<ulong> state = stackalloc ulong[8];
        Initialize(state, destination.Length);
        UInt128 count = 0;
        int processed = CompressNonFinal(state, input, ref count);
        Finish(state, input[processed..], (UInt128)input.Length, destination);
        return Blake2bStatus.Success;
    }

    private static void Initialize(Span<ulong> state, int size)
    {
        InitialState.CopyTo(state);
        state[0] ^= 0x01010000UL | (ulong)size;
    }

    private static int CompressNonFinal(Span<ulong> state, ReadOnlySpan<byte> input, ref UInt128 count)
    {
        int offset = 0;
        while (input.Length - offset > BlockSize)
        {
            count += BlockSize;
            Compress(state, input.Slice(offset, BlockSize), count, final: false);
            offset += BlockSize;
        }
        return offset;
    }

    private static void Finish(Span<ulong> state, ReadOnlySpan<byte> tail, UInt128 count, Span<byte> output)
    {
        Span<byte> block = stackalloc byte[BlockSize];
        block.Clear();
        tail.CopyTo(block);
        Compress(state, block, count, final: true);
        for (int i = 0; i < output.Length; i++)
            output[i] = unchecked((byte)(state[i / 8] >> (8 * (i % 8))));
    }

    private static void Compress(Span<ulong> state, ReadOnlySpan<byte> input, UInt128 count, bool final)
    {
        Span<ulong> words = stackalloc ulong[16];
        for (int i = 0; i < words.Length; i++)
            words[i] = BinaryPrimitives.ReadUInt64LittleEndian(input[(8 * i)..]);

        ReadOnlySpan<ulong> iv = InitialState;
        ulong v0 = state[0], v1 = state[1], v2 = state[2], v3 = state[3];
        ulong v4 = state[4], v5 = state[5], v6 = state[6], v7 = state[7];
        ulong v8 = iv[0], v9 = iv[1], v10 = iv[2], v11 = iv[3];
        ulong v12 = iv[4] ^ unchecked((ulong)count), v13 = iv[5] ^ (ulong)(count >> 64);
        ulong v14 = iv[6], v15 = iv[7];
        if (final)
            v14 = ~v14;

        ReadOnlySpan<byte> sigma = Sigma;
        for (int round = 0; round < 12; round++)
        {
            ReadOnlySpan<byte> s = sigma.Slice(16 * (round % 10), 16);
            Mix(ref v0, ref v4, ref v8,  ref v12, words[s[0]],  words[s[1]]);
            Mix(ref v1, ref v5, ref v9,  ref v13, words[s[2]],  words[s[3]]);
            Mix(ref v2, ref v6, ref v10, ref v14, words[s[4]],  words[s[5]]);
            Mix(ref v3, ref v7, ref v11, ref v15, words[s[6]],  words[s[7]]);
            Mix(ref v0, ref v5, ref v10, ref v15, words[s[8]],  words[s[9]]);
            Mix(ref v1, ref v6, ref v11, ref v12, words[s[10]], words[s[11]]);
            Mix(ref v2, ref v7, ref v8,  ref v13, words[s[12]], words[s[13]]);
            Mix(ref v3, ref v4, ref v9,  ref v14, words[s[14]], words[s[15]]);
        }
        state[0] ^= v0 ^ v8;
        state[1] ^= v1 ^ v9;
        state[2] ^= v2 ^ v10;
        state[3] ^= v3 ^ v11;
        state[4] ^= v4 ^ v12;
        state[5] ^= v5 ^ v13;
        state[6] ^= v6 ^ v14;
        state[7] ^= v7 ^ v15;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Mix(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ulong x, ulong y)
    {
        unchecked
        {
            a += b + x;
            d = BitOperations.RotateRight(d ^ a, 32);
            c += d;
            b = BitOperations.RotateRight(b ^ c, 24);
            a += b + y;
            d = BitOperations.RotateRight(d ^ a, 16);
            c += d;
            b = BitOperations.RotateRight(b ^ c, 63);
        }
    }
}

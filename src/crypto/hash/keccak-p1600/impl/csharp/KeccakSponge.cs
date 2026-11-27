using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Abc.Cryptography;

/// <summary>Keccak-p[1600,24] and the byte-oriented 1088-bit-rate sponge.</summary>
public sealed class KeccakSponge
{
    public const int RateBytes = 136;
    private static readonly int[] Rotation =
    [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
        41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ];
    private static readonly int[] Pi =
    [
        0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
        23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
    ];
    private static readonly ulong[] Iota =
    [
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
    ];

    private readonly ulong[] lanes = new ulong[25];
    private readonly byte[] pending = new byte[RateBytes];
    private int used;

    public void Reset()
    {
        lanes.AsSpan().Clear();
        pending.AsSpan().Clear();
        used = 0;
    }

    public void Update(ReadOnlySpan<byte> input)
    {
        if (used != 0)
        {
            int count = Math.Min(input.Length, RateBytes - used);
            input[..count].CopyTo(pending.AsSpan(used));
            used += count;
            if (used < RateBytes)
                return;

            Absorb(lanes, pending);
            input = input[count..];
        }

        while (input.Length >= RateBytes)
        {
            Absorb(lanes, input[..RateBytes]);
            input = input[RateBytes..];
        }
        input.CopyTo(pending);
        used = input.Length;
    }

    public byte[] Sha3Digest()
    {
        var digest = new byte[32];
        Encode(FinalizeLanes(0x06), digest);
        return digest;
    }

    public Reader ShakeReader() => new(FinalizeLanes(0x1f));

    private ulong[] FinalizeLanes(byte suffix)
    {
        Span<byte> block = stackalloc byte[RateBytes];
        block.Clear();
        pending.AsSpan(0, used).CopyTo(block);
        block[used] = suffix;
        block[^1] |= 0x80;
        ulong[] snapshot = (ulong[])lanes.Clone();
        Absorb(snapshot, block);
        return snapshot;
    }

    private static void Absorb(Span<ulong> state, ReadOnlySpan<byte> block)
    {
        for (int lane = 0; lane < RateBytes / 8; lane++)
            state[lane] ^= BinaryPrimitives.ReadUInt64LittleEndian(block[(8 * lane)..]);

        Permute(state);
    }

    private static void Encode(ReadOnlySpan<ulong> state, Span<byte> block)
    {
        for (int lane = 0; lane < block.Length / 8; lane++)
            BinaryPrimitives.WriteUInt64LittleEndian(block[(8 * lane)..], state[lane]);
    }

    /// <summary>Apply the 24 rounds to lanes in x + 5*y order.</summary>
    public static void Permute(Span<ulong> state)
    {
        if (state.Length != 25)
            throw new ArgumentException("Keccak-p[1600] requires 25 lanes", nameof(state));

        Span<ulong> parity = stackalloc ulong[5];
        Span<ulong> theta = stackalloc ulong[5];
        Span<ulong> shuffled = stackalloc ulong[25];
        foreach (ulong round in Iota)
        {
            for (int x = 0; x < 5; x++)
                parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

            for (int x = 0; x < 5; x++)
                theta[x] = parity[(x + 4) % 5] ^ BitOperations.RotateLeft(parity[(x + 1) % 5], 1);

            for (int source = 0; source < 25; source++)
                shuffled[Pi[source]] = BitOperations.RotateLeft(state[source] ^ theta[source % 5], Rotation[source]);

            for (int row = 0; row < 25; row += 5)
            {
                ulong a = shuffled[row];
                ulong b = shuffled[row + 1];
                ulong c = shuffled[row + 2];
                ulong d = shuffled[row + 3];
                ulong e = shuffled[row + 4];
                state[row] = a ^ (~b & c);
                state[row + 1] = b ^ (~c & d);
                state[row + 2] = c ^ (~d & e);
                state[row + 3] = d ^ (~e & a);
                state[row + 4] = e ^ (~a & b);
            }
            state[0] ^= round;
        }
    }

    /// <summary>A SHAKE256 snapshot with an independent output cursor.</summary>
    public sealed class Reader
    {
        private readonly ulong[] lanes;
        private readonly byte[] block = new byte[RateBytes];
        private int offset;

        internal Reader(ulong[] lanes)
        {
            this.lanes = lanes;
            Encode(lanes, block);
        }

        public byte[] Read(int length)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            var result = new byte[length];
            ReadInto(result);
            return result;
        }

        public void ReadInto(Span<byte> destination)
        {
            while (!destination.IsEmpty)
            {
                if (offset == RateBytes)
                {
                    Permute(lanes);
                    Encode(lanes, block);
                    offset = 0;
                }
                int count = Math.Min(destination.Length, RateBytes - offset);
                block.AsSpan(offset, count).CopyTo(destination);
                offset += count;
                destination = destination[count..];
            }
        }
    }
}

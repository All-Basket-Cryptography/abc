using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Abc.Cryptography;

/// <summary>RFC 7914 byte-oriented scrypt with an explicit memory limit.</summary>
public static class Scrypt
{
    private const int MaxArrayBytes = int.MaxValue - 64;
    private const int StateWords = 16;

    /// <summary>Return the byte count of the primary work buffers.</summary>
    public static int WorkspaceSize(int cost, int blockSize, int parallel)
        => GetLayout(cost, blockSize, parallel).Workspace;

    /// <summary>Derive an owned result after checking the work-buffer and output budget.</summary>
    public static byte[] Derive(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
                                int cost, int blockSize, int parallel, int length, long memoryLimit)
    {
        Layout layout = GetLayout(cost, blockSize, parallel);
        if (length < 1 || length > MaxArrayBytes)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (memoryLimit < (long)layout.Workspace + length)
            throw new ArgumentOutOfRangeException(nameof(memoryLimit), "scrypt work buffers and output exceed the budget");

        var data = new byte[layout.Lanes];
        var history = new uint[layout.Table / sizeof(uint)];
        var lane = new uint[layout.Stride / sizeof(uint)];
        var reordered = new uint[lane.Length];
        Span<uint> state = stackalloc uint[StateWords];
        Span<uint> scratch = stackalloc uint[StateWords];
        try
        {
            DeriveBlocks(password, salt, data);
            for (int offset = 0; offset < data.Length; offset += layout.Stride)
            {
                Span<byte> bytes = data.AsSpan(offset, layout.Stride);
                for (int i = 0; i < lane.Length; i++)
                    lane[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(i * sizeof(uint))..]);
                Romix(lane, reordered, history, state, scratch, cost);
                for (int i = 0; i < lane.Length; i++)
                    BinaryPrimitives.WriteUInt32LittleEndian(bytes[(i * sizeof(uint))..], lane[i]);
            }
            var output = new byte[length];
            DeriveBlocks(password, data, output);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(history.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(lane.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(reordered.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(scratch));
        }
    }

    private static void DeriveBlocks(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> output)
    {
        if (Pbkdf2Sha256.Derive(password, salt, 1, output) != Pbkdf2Status.Success)
            throw new InvalidOperationException("Unexpected scrypt PBKDF2 input rejection");
    }

    private readonly record struct Layout(int Stride, int Lanes, int Table, int Workspace);

    private static Layout GetLayout(int cost, int blockSize, int parallel)
    {
        if (cost < 2 || (cost & (cost - 1)) != 0)
            throw new ArgumentOutOfRangeException(nameof(cost), "scrypt requires a power-of-two cost above one");
        if (blockSize < 1)
            throw new ArgumentOutOfRangeException(nameof(blockSize));
        if (parallel < 1)
            throw new ArgumentOutOfRangeException(nameof(parallel));
        if (BitOperations.TrailingZeroCount((uint)cost) >= 16L * blockSize)
            throw new ArgumentOutOfRangeException(nameof(cost), "scrypt requires cost below 2^(16r)");

        long stride = 128L * blockSize;
        if (stride > MaxArrayBytes / cost || stride > MaxArrayBytes / parallel)
            throw new ArgumentException("scrypt work buffers exceed the .NET profile size");
        long lanes = stride * parallel;
        long table = stride * cost;
        long workspace = table + lanes + 2 * stride + 128;
        if (workspace > MaxArrayBytes)
            throw new ArgumentException("scrypt work buffers exceed the .NET profile size");
        return new Layout((int)stride, (int)lanes, (int)table, (int)workspace);
    }

    private static void Romix(Span<uint> input, Span<uint> reordered, Span<uint> history,
                              Span<uint> state, Span<uint> scratch, int cost)
    {
        Span<uint> lane = input;
        Span<uint> next = reordered;
        int words = input.Length;
        for (int i = 0; i < cost; i++)
        {
            lane.CopyTo(history[(i * words)..]);
            BlockMix(lane, next, state, scratch);
            Span<uint> previous = lane;
            lane = next;
            next = previous;
        }
        for (int i = 0; i < cost; i++)
        {
            int slot = (int)(lane[words - StateWords] & (uint)(cost - 1)) * words;
            ReadOnlySpan<uint> saved = history.Slice(slot, words);
            for (int j = 0; j < words; j++)
                lane[j] ^= saved[j];
            BlockMix(lane, next, state, scratch);
            Span<uint> previous = lane;
            lane = next;
            next = previous;
        }
        // The 2*N exchanges place the final result back in input.
    }

    private static void BlockMix(ReadOnlySpan<uint> input, Span<uint> output, Span<uint> state, Span<uint> scratch)
    {
        int blocks = input.Length / StateWords;
        input[^StateWords..].CopyTo(state);
        for (int block = 0; block < blocks; block++)
        {
            int offset = block * StateWords;
            for (int i = 0; i < StateWords; i++)
                state[i] ^= input[offset + i];
            Salsa8(state, scratch);
            int position = (block / 2 + (block & 1) * (blocks / 2)) * StateWords;
            state.CopyTo(output[position..]);
        }
    }

    private static void Salsa8(Span<uint> state, Span<uint> scratch)
    {
        state.CopyTo(scratch);
        for (int i = 0; i < 4; i++)
        {
            Quarter(scratch, 0, 4, 8, 12);
            Quarter(scratch, 5, 9, 13, 1);
            Quarter(scratch, 10, 14, 2, 6);
            Quarter(scratch, 15, 3, 7, 11);
            Quarter(scratch, 0, 1, 2, 3);
            Quarter(scratch, 5, 6, 7, 4);
            Quarter(scratch, 10, 11, 8, 9);
            Quarter(scratch, 15, 12, 13, 14);
        }
        for (int i = 0; i < StateWords; i++)
            state[i] = unchecked(state[i] + scratch[i]);
    }

    private static void Quarter(Span<uint> words, int a, int b, int c, int d)
    {
        unchecked
        {
            words[b] ^= BitOperations.RotateLeft(words[a] + words[d], 7);
            words[c] ^= BitOperations.RotateLeft(words[b] + words[a], 9);
            words[d] ^= BitOperations.RotateLeft(words[c] + words[b], 13);
            words[a] ^= BitOperations.RotateLeft(words[d] + words[c], 18);
        }
    }
}

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Abc.Cryptography;

public static class ChaCha20Cipher
{
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int BlockSize = 64;

    public static bool FitsCounter(ulong size, uint counter) =>
        size <= ((ulong)uint.MaxValue + 1 - counter) * BlockSize;

    public static void Block(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<byte> output)
    {
        if (output.Length < BlockSize)
            throw new ArgumentException("ChaCha20 block destination is too short.", nameof(output));
        Span<uint> initial = stackalloc uint[16];
        Span<uint> work = stackalloc uint[16];
        try
        {
            Initialize(key, nonce, counter, initial);
            Compress(initial, work, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(initial));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(work));
        }
    }

    public static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter,
                           ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (!FitsCounter((ulong)input.Length, counter))
            throw new ArgumentOutOfRangeException(nameof(input), "ChaCha20 counter would wrap.");
        if (output.Length < input.Length)
            throw new ArgumentException("ChaCha20 destination is too short.", nameof(output));
        if (input.Overlaps(output[..input.Length], out int offset) && offset != 0)
            throw new ArgumentException("ChaCha20 accepts disjoint or exact in-place buffers.", nameof(output));

        Span<uint> initial = stackalloc uint[16];
        Span<uint> work = stackalloc uint[16];
        Span<byte> stream = stackalloc byte[BlockSize];
        try
        {
            Initialize(key, nonce, counter, initial);
            for (int consumed = 0; consumed < input.Length;)
            {
                initial[12] = counter + (uint)(consumed / BlockSize);
                Compress(initial, work, stream);
                int count = Math.Min(input.Length - consumed, BlockSize);
                for (int j = 0; j < count; j++)
                    output[consumed + j] = (byte)(input[consumed + j] ^ stream[j]);
                consumed += count;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(initial));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(work));
            CryptographicOperations.ZeroMemory(stream);
        }
    }

    private static void Initialize(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<uint> state)
    {
        if (key.Length != KeySize) throw new ArgumentException("ChaCha20 requires a 32-byte key.", nameof(key));
        if (nonce.Length != NonceSize) throw new ArgumentException("ChaCha20 requires a 12-byte nonce.", nameof(nonce));
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4*i)..]);
        state[12] = counter;
        for (int i = 0; i < 3; i++) state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(4*i)..]);
    }

    private static void Compress(ReadOnlySpan<uint> initial, Span<uint> work, Span<byte> output)
    {
        initial.CopyTo(work);
        for (int i = 0; i < 10; i++)
        {
            Quarter(ref work[0], ref work[4], ref work[8], ref work[12]);
            Quarter(ref work[1], ref work[5], ref work[9], ref work[13]);
            Quarter(ref work[2], ref work[6], ref work[10], ref work[14]);
            Quarter(ref work[3], ref work[7], ref work[11], ref work[15]);
            Quarter(ref work[0], ref work[5], ref work[10], ref work[15]);
            Quarter(ref work[1], ref work[6], ref work[11], ref work[12]);
            Quarter(ref work[2], ref work[7], ref work[8], ref work[13]);
            Quarter(ref work[3], ref work[4], ref work[9], ref work[14]);
        }
        for (int i = 0; i < work.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output[(4*i)..], unchecked(work[i] + initial[i]));
    }

    private static void Quarter(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        unchecked
        {
            a += b; d = BitOperations.RotateLeft(d ^ a, 16);
            c += d; b = BitOperations.RotateLeft(b ^ c, 12);
            a += b; d = BitOperations.RotateLeft(d ^ a, 8);
            c += d; b = BitOperations.RotateLeft(b ^ c, 7);
        }
    }
}

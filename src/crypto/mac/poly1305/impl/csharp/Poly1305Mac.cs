using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Abc.Cryptography;

public sealed class Poly1305Mac : IDisposable
{
    public const int KeySize = 32;
    public const int TagSize = 16;
    private const int LimbBits = 26;
    private const ulong LimbMask = (1UL << LimbBits) - 1;

    private readonly ulong[] residue = new ulong[5];
    private readonly ulong[] r = new ulong[5];
    private readonly ulong[] folded = new ulong[5];
    private readonly uint[] pad = new uint[4];
    private readonly byte[] tail = new byte[TagSize];
    private int used;
    private bool closed;

    public Poly1305Mac(ReadOnlySpan<byte> oneTimeKey)
    {
        if (oneTimeKey.Length != KeySize)
            throw new ArgumentException("Poly1305 requires a 32-byte one-time key.", nameof(oneTimeKey));
        Span<byte> clipped = stackalloc byte[TagSize];
        oneTimeKey[..TagSize].CopyTo(clipped);
        for (int i = 0; i < 4; i++)
        {
            pad[i] = BinaryPrimitives.ReadUInt32LittleEndian(oneTimeKey[(TagSize + 4*i)..]);
            clipped[4*i + 3] &= 15;
        }
        clipped[4] &= 252;
        clipped[8] &= 252;
        clipped[12] &= 252;
        Decode(clipped, r);
        CryptographicOperations.ZeroMemory(clipped);
        for (int i = 1; i < r.Length; i++) folded[i] = 5 * r[i];
    }

    public void Update(ReadOnlySpan<byte> input)
    {
        ObjectDisposedException.ThrowIf(closed, this);
        if (used != 0)
        {
            int count = Math.Min(TagSize - used, input.Length);
            input[..count].CopyTo(tail.AsSpan(used));
            used += count;
            input = input[count..];
            if (used < TagSize) return;
            Absorb(tail, 1UL << 24);
        }
        while (input.Length >= TagSize)
        {
            Absorb(input[..TagSize], 1UL << 24);
            input = input[TagSize..];
        }
        input.CopyTo(tail);
        used = input.Length;
    }

    public void Finish(Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(closed, this);
        if (output.Length < TagSize)
            throw new ArgumentException("Poly1305 tag destination is too short.", nameof(output));
        if (used != 0)
        {
            tail.AsSpan(used).Clear();
            tail[used] = 1;
            Absorb(tail, 0);
        }

        Carry(residue);
        Span<ulong> reduced = stackalloc ulong[5];
        residue.CopyTo(reduced);
        reduced[0] += 5;
        for (int i = 0; i < 4; i++)
        {
            reduced[i + 1] += reduced[i] >> LimbBits;
            reduced[i] &= LimbMask;
        }
        ulong select = unchecked(0UL - (reduced[4] >> LimbBits));
        reduced[4] &= LimbMask;
        for (int i = 0; i < 5; i++) residue[i] ^= (residue[i] ^ reduced[i]) & select;

        Span<uint> words = stackalloc uint[4]
        {
            unchecked((uint)(residue[0] | residue[1] << 26)),
            unchecked((uint)(residue[1] >> 6 | residue[2] << 20)),
            unchecked((uint)(residue[2] >> 12 | residue[3] << 14)),
            unchecked((uint)(residue[3] >> 18 | residue[4] << 8)),
        };
        ulong carry = 0;
        for (int i = 0; i < 4; i++)
        {
            ulong sum = (ulong)words[i] + pad[i] + carry;
            BinaryPrimitives.WriteUInt32LittleEndian(output[(4*i)..], unchecked((uint)sum));
            carry = sum >> 32;
        }
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(reduced));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(words));
        Dispose();
    }

    public static void Authenticate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        using var mac = new Poly1305Mac(key);
        mac.Update(message);
        mac.Finish(output);
    }

    public void Dispose()
    {
        closed = true;
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(residue.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(r.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(folded.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pad.AsSpan()));
        CryptographicOperations.ZeroMemory(tail);
        used = 0;
    }

    private static void Decode(ReadOnlySpan<byte> block, Span<ulong> limbs)
    {
        ulong t0 = BinaryPrimitives.ReadUInt32LittleEndian(block);
        ulong t1 = BinaryPrimitives.ReadUInt32LittleEndian(block[4..]);
        ulong t2 = BinaryPrimitives.ReadUInt32LittleEndian(block[8..]);
        ulong t3 = BinaryPrimitives.ReadUInt32LittleEndian(block[12..]);
        limbs[0] = t0 & LimbMask;
        limbs[1] = (t0 >> 26 | t1 << 6) & LimbMask;
        limbs[2] = (t1 >> 20 | t2 << 12) & LimbMask;
        limbs[3] = (t2 >> 14 | t3 << 18) & LimbMask;
        limbs[4] = t3 >> 8;
    }

    private void Absorb(ReadOnlySpan<byte> block, ulong marker)
    {
        Span<ulong> h = stackalloc ulong[5];
        Decode(block, h);
        for (int i = 0; i < 5; i++) h[i] += residue[i];
        h[4] += marker;
        // Terms at degree five or higher fold through (2^26)^5 = 5 modulo p.
        residue[0] = h[0]*r[0] + h[1]*folded[4] + h[2]*folded[3] + h[3]*folded[2] + h[4]*folded[1];
        residue[1] = h[0]*r[1] + h[1]*r[0] + h[2]*folded[4] + h[3]*folded[3] + h[4]*folded[2];
        residue[2] = h[0]*r[2] + h[1]*r[1] + h[2]*r[0] + h[3]*folded[4] + h[4]*folded[3];
        residue[3] = h[0]*r[3] + h[1]*r[2] + h[2]*r[1] + h[3]*r[0] + h[4]*folded[4];
        residue[4] = h[0]*r[4] + h[1]*r[3] + h[2]*r[2] + h[3]*r[1] + h[4]*r[0];
        Carry(residue);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(h));
    }

    private static void Carry(Span<ulong> h)
    {
        for (int i = 0; i < 4; i++)
        {
            h[i + 1] += h[i] >> LimbBits;
            h[i] &= LimbMask;
        }
        h[0] += (h[4] >> LimbBits) * 5;
        h[4] &= LimbMask;
        h[1] += h[0] >> LimbBits;
        h[0] &= LimbMask;
    }
}

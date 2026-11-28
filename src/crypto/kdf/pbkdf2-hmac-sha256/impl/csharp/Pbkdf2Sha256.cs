using System;
using System.Buffers.Binary;

namespace Abc.Cryptography;

public enum Pbkdf2Status
{
    Success,
    InvalidIterations,
    InvalidOutputLength,
    SaltOverlapsOutput,
}

/// <summary>RFC 8018 PBKDF2 over byte strings using portable managed HMAC-SHA-256.</summary>
public static class Pbkdf2Sha256
{
    public static Pbkdf2Status Derive(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
                                      uint iterations, Span<byte> output)
    {
        if (iterations == 0)
            return Pbkdf2Status.InvalidIterations;
        if (output.IsEmpty)
            return Pbkdf2Status.InvalidOutputLength;
        if (salt.Overlaps(output))
            return Pbkdf2Status.SaltOverlapsOutput;

        // Normalize once before starting the PRF loop or modifying an overlapping password.
        Span<byte> key = stackalloc byte[Sha256Hasher.BlockSize];
        if (password.Length > key.Length)
        {
            _ = Sha256Hasher.Hash(password, key);
            DeriveBlocks(key[..HmacSha256.TagSize], salt, iterations, output);
        }
        else
        {
            password.CopyTo(key);
            DeriveBlocks(key[..password.Length], salt, iterations, output);
        }
        return Pbkdf2Status.Success;
    }

    private static void DeriveBlocks(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt,
                                     uint iterations, Span<byte> output)
    {
        Span<byte> index = stackalloc byte[sizeof(uint)];
        Span<byte> previous = stackalloc byte[HmacSha256.TagSize];
        Span<byte> accumulated = stackalloc byte[HmacSha256.TagSize];
        for (int offset = 0; offset < output.Length;)
        {
            uint block = (uint)(offset / HmacSha256.TagSize + 1);
            BinaryPrimitives.WriteUInt32BigEndian(index, block);
            var first = new HmacSha256(key);
            _ = first.Update(salt);
            _ = first.Update(index);
            _ = first.Digest(previous);
            previous.CopyTo(accumulated);
            for (uint round = 1; round < iterations; ++round)
            {
                // Authenticate reads the previous block before replacing it.
                _ = HmacSha256.Authenticate(key, previous, previous);
                for (int i = 0; i < accumulated.Length; ++i)
                    accumulated[i] ^= previous[i];
            }
            int count = Math.Min(accumulated.Length, output.Length - offset);
            accumulated[..count].CopyTo(output[offset..]);
            offset += count;
        }
    }
}

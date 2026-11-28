using System;

namespace Abc.Cryptography;

/// <summary>Streaming full-tag HMAC-SHA-256 over the portable managed SHA-256 core.</summary>
public sealed class HmacSha256
{
    public const int TagSize = Sha256Hasher.DigestSize;
    public const ulong MaxMessageBytes = Sha256Hasher.MaxMessageBytes - Sha256Hasher.BlockSize;

    private readonly Sha256Hasher inner = new();
    private readonly byte[] outerPad = new byte[Sha256Hasher.BlockSize];

    public HmacSha256(ReadOnlySpan<byte> key)
    {
        Span<byte> pad = stackalloc byte[Sha256Hasher.BlockSize];
        pad.Clear();
        if (key.Length > pad.Length)
        {
            // A span's length fits in int and the destination has room for SHA-256.
            _ = Sha256Hasher.Hash(key, pad);
        }
        else
        {
            key.CopyTo(pad);
        }
        for (int i = 0; i < pad.Length; ++i)
        {
            outerPad[i] = (byte)(pad[i] ^ 0x5c);
            pad[i] ^= 0x36;
        }
        _ = inner.Update(pad);
    }

    /// <summary>Append input. A length rejection preserves the digest state.</summary>
    public Sha256Status Update(ReadOnlySpan<byte> input) => inner.Update(input);

    /// <summary>Write a tag snapshot, preserving the context and the destination suffix.</summary>
    public Sha256Status Digest(Span<byte> destination)
    {
        if (destination.Length < TagSize)
            return Sha256Status.DestinationTooShort;
        Span<byte> intermediate = stackalloc byte[TagSize];
        _ = inner.Digest(intermediate);
        var outer = new Sha256Hasher();
        _ = outer.Update(outerPad);
        _ = outer.Update(intermediate);
        return outer.Digest(destination);
    }

    public static Sha256Status Authenticate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data,
                                          Span<byte> destination)
    {
        if (destination.Length < TagSize)
            return Sha256Status.DestinationTooShort;
        var hmac = new HmacSha256(key);
        Sha256Status status = hmac.Update(data);
        return status == Sha256Status.Success ? hmac.Digest(destination) : status;
    }
}

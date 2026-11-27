using System;

namespace Abc.Cryptography;

/// <summary>Byte-oriented SHA3-256 with a non-destructive digest snapshot.</summary>
public sealed class Sha3_256
{
    private readonly KeccakSponge sponge = new();

    public void Update(ReadOnlySpan<byte> input) => sponge.Update(input);

    public void Reset() => sponge.Reset();

    public byte[] Digest() => sponge.Sha3Digest();

    public static byte[] HashData(ReadOnlySpan<byte> input)
    {
        var hasher = new Sha3_256();
        hasher.Update(input);
        return hasher.Digest();
    }
}

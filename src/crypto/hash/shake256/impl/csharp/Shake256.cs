using System;

namespace Abc.Cryptography;

/// <summary>Byte-oriented SHAKE256 with independent output readers.</summary>
public sealed class Shake256
{
    private readonly KeccakSponge sponge = new();

    public void Update(ReadOnlySpan<byte> input) => sponge.Update(input);

    public void Reset() => sponge.Reset();

    public KeccakSponge.Reader Finish() => sponge.ShakeReader();

    public static byte[] HashData(ReadOnlySpan<byte> input, int outputLength)
    {
        var absorber = new Shake256();
        absorber.Update(input);
        return absorber.Finish().Read(outputLength);
    }
}

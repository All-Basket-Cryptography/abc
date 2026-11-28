using System;
using System.Linq;
using System.Security.Cryptography;
using Abc.Cryptography;

static void Require(bool passed, string message)
{
    if (!passed)
        throw new InvalidOperationException(message);
}

static void Check(byte[] salt, byte[] ikm, byte[] info, byte[] expectedPrk, byte[] expected)
{
    var prk = new byte[HkdfSha256.PrkSize];
    var output = new byte[expected.Length];
    Require(HkdfSha256.Extract(salt, ikm, prk) == Sha256Status.Success &&
        prk.AsSpan().SequenceEqual(expectedPrk), "extract");
    Require(HkdfSha256.Expand(prk, info, output) == HkdfStatus.Success &&
        output.AsSpan().SequenceEqual(expected), "expand");
    Array.Fill(output, (byte)0xa5);
    Require(HkdfSha256.Derive(salt, ikm, info, output) == HkdfStatus.Success &&
        output.AsSpan().SequenceEqual(expected), "derive");
}

byte[] input = Enumerable.Repeat((byte)0x0b, 22).ToArray();
Check(Convert.FromHexString("000102030405060708090a0b0c"), input, Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9"),
    Convert.FromHexString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
    Convert.FromHexString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
Check([], input, [],
    Convert.FromHexString("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
    Convert.FromHexString("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));

var random = new Random(5869);
int comparisons = 0;
foreach (int saltSize in new[] {0, 1, 32, 64, 65, 129})
{
    foreach (int size in new[] {0, 1, 31, 32, 33, 63, 64, 65, 127, 8159, 8160})
    {
        var salt = new byte[saltSize];
        var ikm = new byte[size % 101];
        var info = new byte[size % 131];
        random.NextBytes(salt);
        random.NextBytes(ikm);
        random.NextBytes(info);
        byte[] prk = HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt);
        byte[] expected = size == 0 ? [] : HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, size, salt, info);
        Check(salt, ikm, info, prk, expected);
        ++comparisons;
    }
}
foreach (int size in new[] {33, 64, 65, 131})
{
    var prk = new byte[size];
    var info = new byte[65];
    random.NextBytes(prk);
    random.NextBytes(info);
    byte[] expected = HKDF.Expand(HashAlgorithmName.SHA256, prk, 257, info);
    var overlap = new byte[expected.Length];
    prk.CopyTo(overlap, 0);
    Require(HkdfSha256.Expand(overlap.AsSpan(0, size), info, overlap) == HkdfStatus.Success &&
        overlap.AsSpan().SequenceEqual(expected), "PRK overlap");
    ++comparisons;
}
byte[] sentinel = Enumerable.Repeat((byte)0xa5, HkdfSha256.MaxOutputBytes + 1).ToArray();
Require(HkdfSha256.Expand(new byte[31], [], sentinel.AsSpan(0, 1)) == HkdfStatus.PrkTooShort, "short PRK");
Require(HkdfSha256.Expand(new byte[32], [], sentinel) == HkdfStatus.OutputTooLong, "oversized output");
Require(HkdfSha256.Expand(new byte[32], sentinel.AsSpan(0, 32), sentinel.AsSpan(0, 1)) ==
    HkdfStatus.InfoOverlapsOutput, "info alias");
Require(sentinel.All(value => value == 0xa5), "rejected operation wrote output");
Console.WriteLine($"{{\"known_answers\":2,\"comparisons\":{comparisons},\"rejection_atomicity\":true}}");

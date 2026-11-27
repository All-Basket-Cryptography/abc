using System;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Abc.Cryptography;

static void Require(bool result, string failure)
{
    if (!result)
        throw new InvalidOperationException(failure);
}

static void OneShot(ReadOnlySpan<byte> input, ReadOnlySpan<byte> expected)
{
    Span<byte> digest = stackalloc byte[Sha512Hasher.DigestSize + 3];
    digest.Fill(0xA5);
    Require(Sha512Hasher.Hash(input, digest) == Sha512Status.Success, "one-shot status");
    Require(digest[..Sha512Hasher.DigestSize].SequenceEqual(expected), "one-shot digest");
    Require(digest[Sha512Hasher.DigestSize..].SequenceEqual(new byte[] { 0xA5, 0xA5, 0xA5 }), "destination suffix");
}

static void Streaming(ReadOnlySpan<byte> input, int split, ReadOnlySpan<byte> expected, bool checkPrefix)
{
    var hasher = new Sha512Hasher();
    Span<byte> digest = stackalloc byte[Sha512Hasher.DigestSize];
    Require(hasher.Update(input[..split]) == Sha512Status.Success, "first chunk");
    if (checkPrefix)
    {
        Require(hasher.Digest(digest) == Sha512Status.Success, "prefix status");
        Require(digest.SequenceEqual(SHA512.HashData(input[..split])), "prefix snapshot");
    }
    Require(hasher.Update(default) == Sha512Status.Success, "empty update");
    Require(hasher.Update(input[split..]) == Sha512Status.Success, "second chunk");
    Require(hasher.Digest(digest) == Sha512Status.Success && digest.SequenceEqual(expected), "streaming digest");
    Require(hasher.Digest(digest) == Sha512Status.Success && digest.SequenceEqual(expected), "repeated digest");
}

static void Boundaries()
{
    var hasher = new Sha512Hasher();
    byte[] message = "abc"u8.ToArray();
    byte[] expected = SHA512.HashData(message);
    Require(hasher.Update(message) == Sha512Status.Success, "initial update");
    Array.Clear(message);

    Span<byte> shortDestination = stackalloc byte[Sha512Hasher.DigestSize - 1];
    shortDestination.Fill(0xA5);
    Require(hasher.Digest(shortDestination) == Sha512Status.DestinationTooShort, "short snapshot destination");
    Require(Sha512Hasher.Hash("abc"u8, shortDestination) == Sha512Status.DestinationTooShort, "short one-shot destination");
    foreach (byte b in shortDestination)
        Require(b == 0xA5, "rejection changed the destination");

    Span<byte> digest = stackalloc byte[Sha512Hasher.DigestSize];
    Require(hasher.Digest(digest) == Sha512Status.Success && digest.SequenceEqual(expected), "context kept caller bytes");

    // Exercise counter rejection without constructing an enormous input.
    FieldInfo counter = typeof(Sha512Hasher).GetField("length", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("missing length counter");
    counter.SetValue(hasher, Sha512Hasher.MaxMessageBytes);
    Require(hasher.Update("x"u8) == Sha512Status.MessageTooLong, "over-limit rejection");
    Require((UInt128)counter.GetValue(hasher)! == Sha512Hasher.MaxMessageBytes, "rejection changed the counter");
    Require(hasher.Update(default) == Sha512Status.Success, "empty update at limit");
    counter.SetValue(hasher, (UInt128)3);
    Require(hasher.Update("d"u8) == Sha512Status.Success, "update after rejection");
    Require(hasher.Digest(digest) == Sha512Status.Success && digest.SequenceEqual(SHA512.HashData("abcd"u8)), "rejection changed the message");

    counter.SetValue(hasher, (UInt128)ulong.MaxValue);
    Require(hasher.Update("x"u8) == Sha512Status.Success, "128-bit byte counter carry");
    Require((UInt128)counter.GetValue(hasher)! == (UInt128.One << 64), "counter did not carry");

    hasher.Reset();
    Require(hasher.Digest(digest) == Sha512Status.Success && digest.SequenceEqual(SHA512.HashData(ReadOnlySpan<byte>.Empty)), "reset");
    "abc"u8.CopyTo(digest);
    Require(Sha512Hasher.Hash(digest[..3], digest) == Sha512Status.Success && digest.SequenceEqual(expected), "overlapping spans");
}

static object Checks()
{
    byte[] million = new byte[1_000_000];
    Array.Fill(million, (byte)'a');
    (byte[] Input, string Digest)[] vectors =
    [
        ([], "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        ("abc"u8.ToArray(), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (Encoding.ASCII.GetBytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
        (million, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"),
    ];
    int snapshots = 0;
    foreach (var vector in vectors)
    {
        byte[] expected = Convert.FromHexString(vector.Digest);
        OneShot(vector.Input, expected);
        Streaming(vector.Input, vector.Input.Length / 2, expected, checkPrefix: true);
        ++snapshots;
    }

    int[] boundaries = [0, 1, 2, 31, 32, 110, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257,
                        383, 384, 511, 512, 1024, 4096, 65536];
    var random = new Random(1804);
    int comparisons = 0, splits = 0;
    for (int i = 0; i < boundaries.Length + 128; ++i)
    {
        int length = i < boundaries.Length ? boundaries[i] : random.Next(4097);
        byte[] input = new byte[length];
        random.NextBytes(input);
        byte[] expected = SHA512.HashData(input);
        OneShot(input, expected);
        ++comparisons;
        Streaming(input, input.Length / 2, expected, checkPrefix: true);
        ++snapshots;
        if (length <= 257)
        {
            for (int split = 0; split <= length; ++split)
            {
                Streaming(input, split, expected, checkPrefix: false);
                ++splits;
            }
        }
    }
    Boundaries();
    return new { knownAnswers = vectors.Length, comparisons, prefixSnapshots = snapshots, streamingSplits = splits,
                 oracle = "System.Security.Cryptography.SHA512.HashData", runtime = Environment.Version.ToString() };
}

static object Benchmark()
{
    byte[] input = new byte[1 << 20];
    for (int i = 0; i < input.Length; ++i)
        input[i] = unchecked((byte)(i * 73 + 11));
    Span<byte> digest = stackalloc byte[Sha512Hasher.DigestSize];
    for (int i = 0; i < 4; ++i)
        Require(Sha512Hasher.Hash(input, digest) == Sha512Status.Success, "benchmark warm-up");
    double[] samples = new double[7];
    double[] oracleSamples = new double[samples.Length];
    for (int sample = 0; sample < samples.Length; ++sample)
    {
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < 16; ++i)
            Require(Sha512Hasher.Hash(input, digest) == Sha512Status.Success, "benchmark hash");
        samples[sample] = 16.0 / Stopwatch.GetElapsedTime(start).TotalSeconds;
        start = Stopwatch.GetTimestamp();
        for (int i = 0; i < 16; ++i)
            SHA512.HashData(input, digest);
        oracleSamples[sample] = 16.0 / Stopwatch.GetElapsedTime(start).TotalSeconds;
    }
    return new { messageBytes = input.Length, hashesPerBatch = 16, samplesMibPerSecond = samples,
                 oracleSamplesMibPerSecond = oracleSamples };
}

Console.WriteLine(JsonSerializer.Serialize(args.Length == 1 && args[0] == "--benchmark" ? Benchmark() : Checks()));

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
    Span<byte> digest = stackalloc byte[Sha256Hasher.DigestSize + 3];
    digest.Fill(0xA5);
    Require(Sha256Hasher.Hash(input, digest) == Sha256Status.Success, "one-shot status");
    Require(digest[..Sha256Hasher.DigestSize].SequenceEqual(expected), "one-shot digest");
    Require(digest[Sha256Hasher.DigestSize..].SequenceEqual(new byte[] { 0xA5, 0xA5, 0xA5 }), "destination suffix");
}

static void Streaming(ReadOnlySpan<byte> input, int split, ReadOnlySpan<byte> expected, bool checkPrefix)
{
    var hasher = new Sha256Hasher();
    Span<byte> digest = stackalloc byte[Sha256Hasher.DigestSize];
    Require(hasher.Update(input[..split]) == Sha256Status.Success, "first chunk");
    if (checkPrefix)
    {
        Require(hasher.Digest(digest) == Sha256Status.Success, "prefix status");
        Require(digest.SequenceEqual(SHA256.HashData(input[..split])), "prefix snapshot");
    }
    Require(hasher.Update(default) == Sha256Status.Success, "empty update");
    Require(hasher.Update(input[split..]) == Sha256Status.Success, "second chunk");
    Require(hasher.Digest(digest) == Sha256Status.Success && digest.SequenceEqual(expected), "streaming digest");
    Require(hasher.Digest(digest) == Sha256Status.Success && digest.SequenceEqual(expected), "repeated digest");
}

static void Boundaries()
{
    var hasher = new Sha256Hasher();
    byte[] message = "abc"u8.ToArray();
    byte[] expected = SHA256.HashData(message);
    Require(hasher.Update(message) == Sha256Status.Success, "initial update");
    Array.Clear(message);

    Span<byte> shortDestination = stackalloc byte[Sha256Hasher.DigestSize - 1];
    shortDestination.Fill(0xA5);
    Require(hasher.Digest(shortDestination) == Sha256Status.DestinationTooShort, "short snapshot destination");
    Require(Sha256Hasher.Hash("abc"u8, shortDestination) == Sha256Status.DestinationTooShort, "short one-shot destination");
    foreach (byte b in shortDestination)
        Require(b == 0xA5, "rejection changed the destination");

    Span<byte> digest = stackalloc byte[Sha256Hasher.DigestSize];
    Require(hasher.Digest(digest) == Sha256Status.Success && digest.SequenceEqual(expected), "context kept caller bytes");

    // Exercise counter rejection without constructing an enormous input.
    FieldInfo counter = typeof(Sha256Hasher).GetField("length", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("missing length counter");
    counter.SetValue(hasher, Sha256Hasher.MaxMessageBytes);
    Require(hasher.Update("x"u8) == Sha256Status.MessageTooLong, "over-limit rejection");
    Require((ulong)counter.GetValue(hasher)! == Sha256Hasher.MaxMessageBytes, "rejection changed the counter");
    Require(hasher.Update(default) == Sha256Status.Success, "empty update at limit");
    counter.SetValue(hasher, 3UL);
    Require(hasher.Update("d"u8) == Sha256Status.Success, "update after rejection");
    Require(hasher.Digest(digest) == Sha256Status.Success && digest.SequenceEqual(SHA256.HashData("abcd"u8)), "rejection changed the message");

    hasher.Reset();
    Require(hasher.Digest(digest) == Sha256Status.Success && digest.SequenceEqual(SHA256.HashData(ReadOnlySpan<byte>.Empty)), "reset");
    "abc"u8.CopyTo(digest);
    Require(Sha256Hasher.Hash(digest[..3], digest) == Sha256Status.Success && digest.SequenceEqual(expected), "overlapping spans");
}

static object Checks()
{
    byte[] million = new byte[1_000_000];
    Array.Fill(million, (byte)'a');
    (byte[] Input, string Digest)[] vectors =
    [
        ([], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc"u8.ToArray(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (million, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ];
    int snapshots = 0;
    foreach (var vector in vectors)
    {
        byte[] expected = Convert.FromHexString(vector.Digest);
        OneShot(vector.Input, expected);
        Streaming(vector.Input, vector.Input.Length / 2, expected, checkPrefix: true);
        ++snapshots;
    }

    int[] boundaries = [0, 1, 2, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129,
                        255, 256, 257, 511, 512, 1024, 4096, 65536];
    var random = new Random(1804);
    int comparisons = 0, splits = 0;
    for (int i = 0; i < boundaries.Length + 128; ++i)
    {
        int length = i < boundaries.Length ? boundaries[i] : random.Next(4097);
        byte[] input = new byte[length];
        random.NextBytes(input);
        byte[] expected = SHA256.HashData(input);
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
                 oracle = "System.Security.Cryptography.SHA256.HashData", runtime = Environment.Version.ToString() };
}

static object Benchmark()
{
    byte[] input = new byte[1 << 20];
    for (int i = 0; i < input.Length; ++i)
        input[i] = unchecked((byte)(i * 73 + 11));
    Span<byte> digest = stackalloc byte[Sha256Hasher.DigestSize];
    for (int i = 0; i < 4; ++i)
        Require(Sha256Hasher.Hash(input, digest) == Sha256Status.Success, "benchmark warm-up");
    double[] samples = new double[7];
    for (int sample = 0; sample < samples.Length; ++sample)
    {
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < 16; ++i)
            Require(Sha256Hasher.Hash(input, digest) == Sha256Status.Success, "benchmark hash");
        samples[sample] = 16.0 / Stopwatch.GetElapsedTime(start).TotalSeconds;
    }
    return new { messageBytes = input.Length, hashesPerBatch = 16, samplesMibPerSecond = samples };
}

Console.WriteLine(JsonSerializer.Serialize(args.Length == 1 && args[0] == "--benchmark" ? Benchmark() : Checks()));

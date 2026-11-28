using System;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Abc.Cryptography;

if (args.Length == 1 && args[0] == "--benchmark")
    Benchmark();
else
{
    CheckBoundaries();
    CheckFixtures();
}

static void CheckFixtures()
{
    int knownAnswers = 0, opensslComparisons = 0, hashlibComparisons = 0, snapshots = 0, streamingSplits = 0;
    while (Console.ReadLine() is string role)
    {
        byte[] input = ReadHex(), expected = ReadHex(), prefix = ReadHex();
        int size = expected.Length, middle = input.Length / 2;
        switch (role)
        {
            case "known": knownAnswers++; break;
            case "openssl": opensslComparisons++; break;
            case "variable": hashlibComparisons++; break;
            default: throw new InvalidOperationException($"Unknown fixture role {role}");
        }

        var output = new byte[size + 2];
        Array.Fill(output, (byte)0xa5);
        Require(Blake2bHasher.Hash(input, output.AsSpan(1, size)) == Blake2bStatus.Success
            && output.AsSpan(1, size).SequenceEqual(expected) && output[0] == 0xa5 && output[^1] == 0xa5,
            "one-shot digest and output canaries");
        var stream = new Blake2bHasher(size);
        Require(stream.Update(input.AsSpan(0, middle)) == Blake2bStatus.Success, "add prefix");
        Snapshot(stream, prefix, output);
        Require(stream.Update(input.AsSpan(middle)) == Blake2bStatus.Success, "continue after snapshot");
        Snapshot(stream, expected, output);
        snapshots++;

        if (input.Length <= 257 && size is 1 or 31 or 64)
        {
            for (int split = 0; split <= input.Length; split++)
            {
                stream.Reset();
                Require(stream.Update(input.AsSpan(0, split)) == Blake2bStatus.Success
                    && stream.Update(ReadOnlySpan<byte>.Empty) == Blake2bStatus.Success
                    && stream.Update(input.AsSpan(split)) == Blake2bStatus.Success, "two-chunk update");
                Snapshot(stream, expected, output);
                streamingSplits++;
            }
        }
    }
    Require(knownAnswers > 0 && opensslComparisons > 0 && hashlibComparisons > 0, "incomplete fixtures");
    Console.WriteLine(JsonSerializer.Serialize(new { knownAnswers, opensslComparisons, hashlibComparisons,
        snapshots, streamingSplits }));
}

static void CheckBoundaries()
{
    Require(new Blake2bHasher().DigestSize == 64, "default size");
    foreach (int invalid in new[] { -1, 0, 65 })
    {
        try
        {
            _ = new Blake2bHasher(invalid);
            throw new InvalidOperationException("accepted invalid digest size");
        }
        catch (ArgumentOutOfRangeException error) when (error.ParamName == "digestSize") { }
    }

    var input = new byte[129];
    for (int i = 0; i < input.Length; i++)
        input[i] = (byte)i;
    byte[] owned = (byte[])input.Clone();
    byte[] expected = new byte[31], guarded = new byte[33], invalidOutput = new byte[65];
    Array.Fill(guarded, (byte)0xa5);
    Array.Fill(invalidOutput, (byte)0xa5);
    var stream = new Blake2bHasher(31);
    Require(stream.Update(input.AsSpan(0, 128)) == Blake2bStatus.Success, "absorb exact block");
    Require(Blake2bHasher.Hash(owned.AsSpan(0, 128), expected) == Blake2bStatus.Success, "exact block reference");
    input.AsSpan(0, 128).Clear();
    Snapshot(stream, expected, guarded);
    Require(stream.Digest(invalidOutput.AsSpan(0, 30)) == Blake2bStatus.InvalidDigestSize
        && Blake2bHasher.Hash(input, invalidOutput) == Blake2bStatus.InvalidDigestSize
        && Blake2bHasher.Hash(input, Span<byte>.Empty) == Blake2bStatus.InvalidDigestSize
        && invalidOutput.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0, "rejected output stays untouched");
    Snapshot(stream, expected, guarded);
    Require(stream.Update(input.AsSpan(128)) == Blake2bStatus.Success, "extend owned pending data");
    Require(Blake2bHasher.Hash(owned, expected) == Blake2bStatus.Success, "two-block reference");
    Snapshot(stream, expected, guarded);
    Require(Blake2bHasher.Hash(owned, owned.AsSpan(7, 31)) == Blake2bStatus.Success
        && owned.AsSpan(7, 31).SequenceEqual(expected)
        && owned[6] == 6 && owned[38] == 38, "overlapping one-shot spans");
    stream.Reset();
    Require(stream.DigestSize == 31 && Blake2bHasher.Hash(ReadOnlySpan<byte>.Empty, expected) == Blake2bStatus.Success,
        "reset retains configured size");
    Snapshot(stream, expected, guarded);

    FieldInfo bytes = typeof(Blake2bHasher).GetField("compressedBytes", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("missing private counter for boundary fixture");
    bytes.SetValue(stream, ((UInt128)5 << 64) + (ulong.MaxValue - 127));
    Require(stream.Update(input.AsSpan(0, 128)) == Blake2bStatus.Success
        && stream.Update(input.AsSpan(128)) == Blake2bStatus.Success
        && (UInt128)bytes.GetValue(stream)! == ((UInt128)6 << 64), "carry crosses low word");
    stream.Reset();
    bytes.SetValue(stream, UInt128.MaxValue - 127);
    Require(stream.Update(input.AsSpan(0, 127)) == Blake2bStatus.Success, "maximum byte count accepted");
    Require(stream.Digest(expected) == Blake2bStatus.Success, "maximum byte count snapshot");
    Require(stream.Update(input.AsSpan(0, 1)) == Blake2bStatus.MessageTooLong
        && stream.Update(ReadOnlySpan<byte>.Empty) == Blake2bStatus.Success, "overflow and empty update status");
    Snapshot(stream, expected, guarded);
}

static byte[] ReadHex() => Convert.FromHexString(Console.ReadLine() ?? throw new InvalidOperationException("Incomplete fixture"));

static void Snapshot(Blake2bHasher stream, byte[] expected, byte[] guarded)
{
    Array.Fill(guarded, (byte)0xa5);
    Span<byte> digest = guarded.AsSpan(1, expected.Length);
    Require(stream.Digest(digest) == Blake2bStatus.Success && digest.SequenceEqual(expected)
        && guarded[0] == 0xa5 && guarded[^1] == 0xa5, "snapshot digest and output canaries");
}

static void Benchmark()
{
    var input = new byte[1 << 20];
    for (int i = 0; i < input.Length; i++)
        input[i] = unchecked((byte)(37 * i + 11));
    Span<byte> digest = stackalloc byte[64];
    for (int i = 0; i < 16; i++)
        Require(Blake2bHasher.Hash(input, digest) == Blake2bStatus.Success, "benchmark warmup");

    var samples = new double[7];
    var allocatedBytes = new long[samples.Length];
    for (int batch = 0; batch < samples.Length; batch++)
    {
        long before = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < 16; i++)
            Require(Blake2bHasher.Hash(input, digest) == Blake2bStatus.Success, "benchmark digest");
        samples[batch] = 16 / Stopwatch.GetElapsedTime(start).TotalSeconds;
        allocatedBytes[batch] = GC.GetAllocatedBytesForCurrentThread() - before;
    }
    Console.WriteLine(JsonSerializer.Serialize(new { messageBytes = input.Length, hashesPerBatch = 16, samples,
        allocatedBytes }));
}

static void Require(bool success, string detail)
{
    if (!success)
        throw new InvalidOperationException(detail);
}

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Abc.Cryptography;

Require(Aes256GcmCipher.IsSupported, ".NET AES-GCM is unavailable");
if (args is ["--benchmark"])
{
    Benchmarks();
    return;
}

int cases = 0;
while (Console.ReadLine() is string line)
{
    var rows = Array.ConvertAll(line.Split(':'), Convert.FromHexString);
    Require(rows.Length == 6, "fixture fields");
    byte[] key = rows[0], nonce = rows[1], aad = rows[2], plaintext = rows[3], encrypted = rows[4], tag = rows[5];
    using var cipher = new Aes256GcmCipher(key);
    byte[] output = new byte[plaintext.Length + 2], tagOutput = new byte[18];
    Array.Fill(output, (byte)0xa5);
    Array.Fill(tagOutput, (byte)0xa5);
    cipher.Seal(nonce, aad, plaintext, output.AsSpan(1, plaintext.Length), tagOutput.AsSpan(1, 16));
    Require(output.AsSpan(1, plaintext.Length).SequenceEqual(encrypted) && tagOutput.AsSpan(1, 16).SequenceEqual(tag),
        "detached seal");
    Require(cipher.Open(nonce, aad, encrypted, tag, output.AsSpan(1, plaintext.Length))
        && output.AsSpan(1, plaintext.Length).SequenceEqual(plaintext)
        && output[0] == 0xa5 && output[^1] == 0xa5 && tagOutput[0] == 0xa5 && tagOutput[^1] == 0xa5,
        "detached open and canaries");

    // Seed the shifted input with the oracle ciphertext and check only open.
    var overlap = new byte[encrypted.Length + 7];
    encrypted.CopyTo(overlap, 0);
    Require(cipher.Open(nonce, aad, overlap.AsSpan(0, plaintext.Length), tag, overlap.AsSpan(7, plaintext.Length))
        && overlap.AsSpan(7, plaintext.Length).SequenceEqual(plaintext), "shifted open");
    cases++;
}
Require(cases == 274, "fixture corpus size");
int authFailures = Boundaries();
Console.WriteLine(JsonSerializer.Serialize(new { cases, authFailures, framework = RuntimeInformation.FrameworkDescription,
    architecture = RuntimeInformation.ProcessArchitecture.ToString() }));

static int Boundaries()
{
    ExpectArgument(() => _ = new Aes256GcmCipher(new byte[31]));
    var key = new byte[32];
    var nonce = new byte[12];
    byte[] aad = [1, 7, 9], tag = new byte[16];
    using var cipher = new Aes256GcmCipher(key);
    using var provider = new AesGcm(key, 16);
    int rejections = 0;

    foreach (int length in new[] { 0, 1, 1_024, 1_025, 4_096 })
    {
        var input = new byte[length];
        for (int index = 0; index < length; index++) input[index] = unchecked((byte)(71 * index + 99));
        byte[] encrypted = new byte[length], output = new byte[length];
        // Test vectors use the direct provider and receiver under the same nonce.
        BinaryPrimitives.WriteInt32LittleEndian(nonce, length);
        provider.Encrypt(nonce, input, encrypted, tag, aad);
        Require(cipher.Open(nonce, aad, encrypted, tag, output) && output.AsSpan().SequenceEqual(input), "length boundary open");
        Array.Fill(output, (byte)0xa5);
        for (int i = 0; i < tag.Length; i++)
        {
            tag[i] ^= 1;
            Require(!cipher.Open(nonce, aad, encrypted, tag, output)
                && output.AsSpan().IndexOfAnyExcept((byte)0xa5) == -1, "altered tag wrote plaintext");
            tag[i] ^= 1;
            rejections++;
        }
        if (length > 0)
        {
            encrypted[0] ^= 1;
            byte[] before = (byte[])encrypted.Clone();
            Require(!cipher.Open(nonce, aad, encrypted, tag, encrypted)
                && encrypted.AsSpan().SequenceEqual(before), "altered in-place body wrote plaintext");
            encrypted[0] ^= 1;
            rejections++;
        }
        aad[0] ^= 1;
        Require(!cipher.Open(nonce, aad, encrypted, tag, output)
            && output.AsSpan().IndexOfAnyExcept((byte)0xa5) == -1, "altered AAD wrote plaintext");
        aad[0] ^= 1;
        rejections++;
    }

    byte[] shared = new byte[64], ciphertext = new byte[32];
    var plaintext = new byte[32];
    for (int i = 0; i < plaintext.Length; i++) plaintext[i] = (byte)i;
    aad.CopyTo(shared, 7);
    var expectedTag = new byte[16];
    // Use a separate fixture key for the alias comparison.
    var aliasKey = (byte[])key.Clone();
    aliasKey[0] = 83;
    using var aliasCipher = new Aes256GcmCipher(aliasKey);
    using var aliasProvider = new AesGcm(aliasKey, 16);
    nonce[11] = 1;
    aliasProvider.Encrypt(nonce, plaintext, ciphertext, expectedTag, aad);
    plaintext.CopyTo(shared, 32);
    aliasCipher.Seal(nonce, shared.AsSpan(7, 3), shared.AsSpan(32, 32), shared.AsSpan(7, 32), tag);
    Require(shared.AsSpan(7, 32).SequenceEqual(ciphertext) && tag.AsSpan().SequenceEqual(expectedTag), "shifted seal with AAD alias");
    var unchanged = (byte[])shared.Clone();
    var unchangedTag = (byte[])tag.Clone();
    ExpectArgument(() => cipher.Seal(nonce, aad, plaintext, shared.AsSpan(0, 32), shared.AsSpan(8, 16)));
    ExpectArgument(() => cipher.Seal(nonce.AsSpan(0, 11), aad, plaintext, shared.AsSpan(0, 32), tag));
    ExpectArgument(() => _ = cipher.Open(nonce, aad, ciphertext, tag.AsSpan(0, 15), shared.AsSpan(0, 32)));
    ExpectArgument(() => _ = cipher.Open(nonce, aad, ciphertext, tag, shared.AsSpan(0, 31)));
    Require(shared.AsSpan().SequenceEqual(unchanged) && tag.AsSpan().SequenceEqual(unchangedTag), "argument output rollback");
    return rejections;
}

static void Benchmarks()
{
    var key = new byte[32];
    using var cipher = new Aes256GcmCipher(key);
    using var provider = new AesGcm(key, 16);
    var nonce = new byte[12];
    ulong sequence = 0;
    var rows = new object[2];
    int row = 0;
    foreach (int messageBytes in new[] { 64, 4_096 })
    {
        var input = new byte[messageBytes];
        var output = new byte[messageBytes];
        var tag = new byte[16];
        var aad = new byte[32];
        int iterations = messageBytes == 64 ? 30_000 : 8_000;
        void Advance() => BinaryPrimitives.WriteUInt64LittleEndian(nonce, sequence++);

        var sdkSeal = Measure(() => { Advance(); cipher.Seal(nonce, aad, input, output, tag); }, iterations);
        var providerSeal = Measure(() => { Advance(); provider.Encrypt(nonce, input, output, tag, aad); }, iterations);
        var sdkOpen = Measure(() => Require(cipher.Open(nonce, aad, output, tag, input), "benchmark open"), iterations);
        var providerOpen = Measure(() => provider.Decrypt(nonce, output, tag, input, aad), iterations);
        rows[row++] = new { messageBytes, iterations, sdkSeal, providerSeal, sdkOpen, providerOpen };
    }
    Console.WriteLine(JsonSerializer.Serialize(rows));
}

static object Measure(Action action, int iterations)
{
    for (int i = 0; i < 10_000; i++) action();
    var samplesNs = new double[7];
    var allocatedBytes = new long[samplesNs.Length];
    for (int sample = 0; sample < samplesNs.Length; sample++)
    {
        long before = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < iterations; i++) action();
        samplesNs[sample] = Stopwatch.GetElapsedTime(start).TotalNanoseconds / iterations;
        allocatedBytes[sample] = GC.GetAllocatedBytesForCurrentThread() - before;
    }
    return new { samplesNs, allocatedBytes };
}

static void Require(bool value, string message)
{
    if (!value) throw new InvalidOperationException(message);
}

static void ExpectArgument(Action action)
{
    try { action(); }
    catch (ArgumentException) { return; }
    throw new InvalidOperationException("Expected ArgumentException");
}

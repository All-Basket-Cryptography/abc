using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Abc.Cryptography;

if (args is ["--benchmark"])
{
    Benchmarks();
    return;
}

int cases = 0;
while (Console.ReadLine() is string line)
{
    var rows = Array.ConvertAll(line.Split(':'), Convert.FromHexString);
    Require(rows.Length == 5, "fixture fields");
    byte[] key = rows[0], plaintext = rows[1], ciphertext = rows[2], encrypted = rows[3], decrypted = rows[4];
    using var cipher = new Aes256Cipher(key);
    var guarded = new byte[18];
    Array.Fill(guarded, (byte)0xa5);
    cipher.EncryptBlock(plaintext, guarded.AsSpan(1, 16));
    Require(guarded.AsSpan(1, 16).SequenceEqual(encrypted), "encrypt reference");
    cipher.DecryptBlock(ciphertext, guarded.AsSpan(1, 16));
    Require(guarded.AsSpan(1, 16).SequenceEqual(decrypted) && guarded[0] == 0xa5 && guarded[^1] == 0xa5,
        "decrypt reference and canaries");

    var overlap = new byte[23];
    plaintext.CopyTo(overlap, 0);
    cipher.EncryptBlock(overlap.AsSpan(0, 16), overlap.AsSpan(7, 16));
    Require(overlap.AsSpan(7, 16).SequenceEqual(encrypted), "shifted encrypt");
    cipher.DecryptBlock(overlap.AsSpan(7, 16), overlap.AsSpan(0, 16));
    Require(overlap.AsSpan(0, 16).SequenceEqual(plaintext), "shifted decrypt");
    cases++;
}

Require(cases == 514, "fixture corpus size");
Expect<ArgumentException>(() => _ = new Aes256Cipher(new byte[31]));
using (var cipher = new Aes256Cipher(new byte[32]))
{
    var output = new byte[16];
    Array.Fill(output, (byte)0xa5);
    Expect<ArgumentException>(() => cipher.EncryptBlock(new byte[15], output));
    Expect<ArgumentException>(() => cipher.DecryptBlock(new byte[16], output.AsSpan(0, 15)));
    cipher.Dispose();
    Expect<ObjectDisposedException>(() => cipher.EncryptBlock(new byte[16], output));
    Require(output.AsSpan().IndexOfAnyExcept((byte)0xa5) == -1, "error changed output");
}
using (Aes provider = Aes.Create())
    Console.WriteLine(JsonSerializer.Serialize(new { cases, framework = RuntimeInformation.FrameworkDescription,
        architecture = RuntimeInformation.ProcessArchitecture.ToString(), provider = provider.GetType().FullName }));

static void Benchmarks()
{
    var key = new byte[32];
    var input = new byte[16];
    var output = new byte[16];
    using var cipher = new Aes256Cipher(key);
    using var aes = Aes.Create();
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.None;
    aes.Key = key;
    using var enc = aes.CreateEncryptor();
    using var dec = aes.CreateDecryptor();
    const int iterations = 100_000;
    var sdkEncrypt = Measure(() => cipher.EncryptBlock(input, output), iterations);
    var providerEncrypt = Measure(() => _ = enc.TransformBlock(input, 0, 16, output, 0), iterations);
    var sdkDecrypt = Measure(() => cipher.DecryptBlock(input, output), iterations);
    var providerDecrypt = Measure(() => _ = dec.TransformBlock(input, 0, 16, output, 0), iterations);
    Console.WriteLine(JsonSerializer.Serialize(new { messageBytes = 16, iterations,
        sdkEncrypt, providerEncrypt, sdkDecrypt, providerDecrypt }));
}

static object Measure(Action action, int iterations)
{
    for (int i = 0; i < 30_000; i++) action();
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

static void Expect<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}");
}

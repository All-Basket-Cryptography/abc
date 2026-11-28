using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using Abc.Cryptography;
using static TestSupport;

if (args[0] == "--benchmark")
{
    Benchmark();
    return;
}

byte[] key = Enumerable.Range(0x80, 32).Select(i => (byte)i).ToArray();
byte[] nonce = Hex("070000004041424344454647");
byte[] aad = Hex("50515253c0c1c2c3c4c5c6c7");
byte[] ciphertext = new byte[RfcMessage.Length];
byte[] tag = new byte[16];
byte[] derived = new byte[64];
ChaCha20Cipher.Block(key, nonce, 0, derived);
Equal(derived.AsSpan(0, 32), Hex("7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff"), "RFC one-time key");
ChaCha20Poly1305Aead.Seal(key, nonce, aad, RfcMessage, ciphertext, tag);
Equal(ciphertext, Hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b6116"), "RFC ciphertext");
Equal(tag, Hex("1ae10b594f09e26a7e902ecbd0600691"), "RFC tag");

byte[] plaintext = new byte[ciphertext.Length + 9];
plaintext.AsSpan().Fill(0xa9);
byte[] saved = (byte[])plaintext.Clone();
for (int index = 0; index < tag.Length; index++)
{
    byte[] wrong = (byte[])tag.Clone();
    wrong[index] ^= 1;
    Require(!ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, ciphertext, wrong, plaintext), "Bad tag accepted.");
    Equal(plaintext, saved, "Tag rejection wrote output.");
    byte[] inPlace = (byte[])ciphertext.Clone();
    Require(!ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, inPlace, wrong, inPlace), "In-place bad tag accepted.");
    Equal(inPlace, ciphertext, "In-place tag rejection wrote output.");
}
Require(!ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, ciphertext, tag.AsSpan(1), plaintext), "Short tag.");
Require(!ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, ciphertext, new byte[17], plaintext), "Long tag.");
Require(!ChaCha20Poly1305Aead.TryOpen(key, nonce, aad.AsSpan(1), ciphertext, tag, plaintext), "Modified AAD.");
byte[] modified = (byte[])ciphertext.Clone();
modified[^1] ^= 1;
Require(!ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, modified, tag, plaintext), "Modified ciphertext.");
Equal(plaintext, saved, "Rejected data modified destination.");
Throws<ArgumentException>(() => ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, ciphertext, tag, plaintext.AsSpan(0, 1)));
Throws<ArgumentException>(() => ChaCha20Poly1305Aead.Seal(key.AsSpan(1), nonce, aad, RfcMessage, plaintext, tag));
Throws<ArgumentException>(() => ChaCha20Poly1305Aead.Seal(key, nonce.AsSpan(1), aad, RfcMessage, plaintext, tag));
Throws<ArgumentException>(() => ChaCha20Poly1305Aead.Seal(key, nonce, aad, RfcMessage, plaintext, plaintext.AsSpan(5, 16)));
Throws<ArgumentException>(() => ChaCha20Poly1305Aead.Seal(key, nonce, aad, RfcMessage, plaintext.AsSpan(0, 1), tag));
Equal(plaintext, saved, "Rejected API sizes wrote destination.");
Equal(tag, Hex("1ae10b594f09e26a7e902ecbd0600691"), "Rejected API sizes wrote the tag.");

Require(ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, ciphertext, tag, plaintext), "RFC open.");
Equal(plaintext.AsSpan(0, ciphertext.Length), RfcMessage, "RFC plaintext");
Equal(plaintext.AsSpan(ciphertext.Length), saved.AsSpan(ciphertext.Length), "Open trailing bytes");
byte[] overlap = (byte[])plaintext.Clone();
ChaCha20Poly1305Aead.Seal(key, nonce, aad, overlap.AsSpan(0, ciphertext.Length), overlap, tag);
Equal(overlap.AsSpan(0, ciphertext.Length), ciphertext, "Seal in place.");
Require(ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, overlap.AsSpan(0, ciphertext.Length), tag, overlap.AsSpan(1)),
    "Open shifted overlap.");
Equal(overlap.AsSpan(1, ciphertext.Length), RfcMessage, "Open shifted plaintext");

var outputs = new List<object>();
using var fixtures = Parse(args[0]);
foreach (var fixture in fixtures.RootElement.EnumerateArray())
{
    key = Field(fixture, "key");
    nonce = Field(fixture, "nonce");
    aad = Field(fixture, "aad");
    byte[] message = Field(fixture, "message");
    ciphertext = new byte[message.Length];
    plaintext = new byte[message.Length];
    ChaCha20Poly1305Aead.Seal(key, nonce, aad, message, ciphertext, tag);
    Require(ChaCha20Poly1305Aead.TryOpen(key, nonce, aad, ciphertext, tag, plaintext), "Fixture open was rejected.");
    Equal(plaintext, message, "Fixture plaintext");
    outputs.Add(new { ciphertext = Wire(ciphertext), tag = Wire(tag) });
}
Console.WriteLine(JsonSerializer.Serialize(new { rfcKnown = 1, boundaries = "passed", outputs }));

static void Benchmark()
{
    byte[] key = new byte[32], nonce = new byte[12], aad = new byte[16];
    byte[] input = new byte[4096], output = new byte[4096], tag = new byte[16];
    const int trials = 7, iterations = 1000;
    double Measure(Action action)
    {
        for (int i = 0; i < iterations; i++) action();
        double[] samples = new double[trials];
        for (int trial = 0; trial < trials; trial++)
        {
            long started = Stopwatch.GetTimestamp();
            for (int i = 0; i < iterations; i++) action();
            samples[trial] = Stopwatch.GetElapsedTime(started).TotalMicroseconds / iterations;
        }
        Array.Sort(samples);
        return samples[trials / 2];
    }
    double portable = Measure(() => ChaCha20Poly1305Aead.Seal(key, nonce, aad, input, output, tag));
    double? provider = null;
    if (System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
    {
        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var reference = new byte[output.Length];
        var referenceTag = new byte[tag.Length];
        aead.Encrypt(nonce, input, reference, referenceTag, aad);
        Equal(output, reference, "Benchmark ciphertext");
        Equal(tag, referenceTag, "Benchmark tag");
        provider = Measure(() => aead.Encrypt(nonce, input, reference, referenceTag, aad));
    }
    Console.WriteLine(JsonSerializer.Serialize(new { trials, iterations, portable_us = portable, provider_us = provider }));
}

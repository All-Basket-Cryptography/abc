using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Abc.Cryptography;
using static TestSupport;

byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
byte[] nonce = Hex("000000090000004a00000000");
byte[] block = new byte[65];
block[64] = 0xa9;
ChaCha20Cipher.Block(key, nonce, 1, block);
Equal(block.AsSpan(0, 64), Hex(
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"), "RFC block");
Require(block[64] == 0xa9, "Block wrote beyond 64 bytes.");

nonce = Hex("000000000000004a00000000");
byte[] ciphertext = (byte[])RfcMessage.Clone();
ChaCha20Cipher.Xor(key, nonce, 1, ciphertext, ciphertext);
Equal(ciphertext, Hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
    "5af90bbf74a35be6b40b8eedf2785e42874d"), "RFC stream");
ChaCha20Cipher.Xor(key, nonce, 1, ciphertext, ciphertext);
Equal(ciphertext, RfcMessage, "In-place stream roundtrip");

foreach (uint counter in new uint[] { 0, 1, uint.MaxValue - 1, uint.MaxValue })
{
    ulong max = ((1UL << 32) - counter) * 64;
    Require(ChaCha20Cipher.FitsCounter(0, counter), "Zero-length counter domain");
    Require(ChaCha20Cipher.FitsCounter(max, counter), "Counter exact bound");
    Require(!ChaCha20Cipher.FitsCounter(max + 1, counter), "Counter overflow bound");
}
byte[] guarded = new byte[66];
guarded.AsSpan().Fill(0xa9);
byte[] saved = (byte[])guarded.Clone();
Throws<ArgumentOutOfRangeException>(() => ChaCha20Cipher.Xor(key, nonce, uint.MaxValue, RfcMessage.AsSpan(0, 65), guarded));
Throws<ArgumentException>(() => ChaCha20Cipher.Xor(key, nonce, 1, RfcMessage.AsSpan(0, 65), guarded.AsSpan(0, 64)));
Throws<ArgumentException>(() => ChaCha20Cipher.Xor(key.AsSpan(1), nonce, 1, RfcMessage.AsSpan(0, 64), guarded));
Throws<ArgumentException>(() => ChaCha20Cipher.Xor(key, nonce.AsSpan(1), 1, RfcMessage.AsSpan(0, 64), guarded));
Throws<ArgumentException>(() => ChaCha20Cipher.Xor(key, nonce, 1, guarded.AsSpan(0, 64), guarded.AsSpan(1)));
Equal(guarded, saved, "Rejected input modified output.");
ChaCha20Cipher.Xor(key, nonce, uint.MaxValue, new byte[64], guarded);
ChaCha20Cipher.Block(key, nonce, uint.MaxValue, block);
Equal(guarded.AsSpan(0, 64), block.AsSpan(0, 64), "Final valid counter");
Equal(guarded.AsSpan(64), saved.AsSpan(64), "Stream trailing bytes");

var outputs = new List<object>();
using var fixtures = Parse(args[0]);
foreach (var fixture in fixtures.RootElement.EnumerateArray())
{
    byte[] message = Field(fixture, "message");
    byte[] result = new byte[message.Length];
    ChaCha20Cipher.Xor(Field(fixture, "key"), Field(fixture, "nonce"),
        fixture.GetProperty("counter").GetUInt32(), message, result);
    outputs.Add(new { ciphertext = Wire(result) });
}
Console.WriteLine(JsonSerializer.Serialize(new { rfcKnown = 2, boundaries = "passed", outputs }));

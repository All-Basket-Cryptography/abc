using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Abc.Cryptography;

static void Require(bool passed, string message)
{
    if (!passed)
        throw new InvalidOperationException(message);
}

static void Check(byte[] key, byte[] input, byte[] expected)
{
    byte[] output = Enumerable.Repeat((byte)0xa5, HmacSha256.TagSize + 3).ToArray();
    Require(HmacSha256.Authenticate(key, input, output) == Sha256Status.Success, "one-shot status");
    Require(output.AsSpan(0, HmacSha256.TagSize).SequenceEqual(expected), "one-shot tag");
    Require(output.AsSpan(HmacSha256.TagSize).SequenceEqual(new byte[] {0xa5, 0xa5, 0xa5}),
        "output suffix");
    var stream = new HmacSha256(key);
    int half = input.Length / 2;
    byte[] prefix = HMACSHA256.HashData(key, input.AsSpan(0, half));
    Array.Fill(key, (byte)0xa5);
    Require(stream.Update(input.AsSpan(0, half)) == Sha256Status.Success, "prefix update");
    Require(stream.Digest(output) == Sha256Status.Success, "prefix digest status");
    Require(output.AsSpan(0, HmacSha256.TagSize).SequenceEqual(prefix), "prefix snapshot");
    byte[] shortOutput = {0xa5, 0xa5};
    Require(stream.Digest(shortOutput) == Sha256Status.DestinationTooShort &&
        shortOutput.AsSpan().SequenceEqual(new byte[] {0xa5, 0xa5}), "short destination");
    Require(stream.Update(input.AsSpan(half)) == Sha256Status.Success, "suffix update");
    Require(stream.Digest(output) == Sha256Status.Success &&
        output.AsSpan(0, HmacSha256.TagSize).SequenceEqual(expected), "stream tag");
    Require(stream.Digest(output) == Sha256Status.Success &&
        output.AsSpan(0, HmacSha256.TagSize).SequenceEqual(expected), "repeat snapshot");
}

Check(Enumerable.Repeat((byte)0x0b, 20).ToArray(), Encoding.ASCII.GetBytes("Hi There"),
    Convert.FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
Check(Encoding.ASCII.GetBytes("Jefe"), Encoding.ASCII.GetBytes("what do ya want for nothing?"),
    Convert.FromHexString("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
Check(Enumerable.Repeat((byte)0xaa, 131).ToArray(),
    Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
    Convert.FromHexString("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

var random = new Random(4231);
int comparisons = 0;
foreach (int keyLength in new[] {0, 1, 31, 32, 63, 64, 65, 131, 1024})
{
    foreach (int length in new[] {0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 257, 1024})
    {
        var key = new byte[keyLength];
        var input = new byte[length];
        random.NextBytes(key);
        random.NextBytes(input);
        Check(key, input, HMACSHA256.HashData(key, input));
        ++comparisons;
    }
}
Console.WriteLine($"{{\"known_answers\":3,\"comparisons\":{comparisons},\"streaming\":true,\"short_destination\":true}}");

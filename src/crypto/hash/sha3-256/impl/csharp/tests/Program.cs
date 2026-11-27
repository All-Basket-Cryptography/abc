using System;
using Abc.Cryptography;

static void Check(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected)
{
    if (!actual.SequenceEqual(expected))
        throw new InvalidOperationException("SHA3-256 mismatch");
}

int cases = 0;
int splits = 0;
while (Console.ReadLine() is string line)
{
    string[] row = line.Split(':');
    byte[] message = Convert.FromHexString(row[0]);
    byte[] expected = Convert.FromHexString(row[1]);
    Check(Sha3_256.HashData(message), expected);
    for (int split = 0; split <= message.Length; split++)
    {
        var hasher = new Sha3_256();
        ReadOnlySpan<byte> prefix = message.AsSpan(0, split);
        hasher.Update(prefix);
        if (System.Security.Cryptography.SHA3_256.IsSupported)
            Check(hasher.Digest(), System.Security.Cryptography.SHA3_256.HashData(prefix));
        else
            Check(hasher.Digest(), Sha3_256.HashData(prefix));

        hasher.Update(ReadOnlySpan<byte>.Empty);
        hasher.Update(message.AsSpan(split));
        Check(hasher.Digest(), expected);
        Check(hasher.Digest(), expected);
        splits++;
    }
    cases++;
}
byte[] input = [1, 2, 3];
byte[] before = Sha3_256.HashData(input);
var hasherTest = new Sha3_256();
hasherTest.Update(input);
input.AsSpan().Clear();
Check(hasherTest.Digest(), before);
hasherTest.Reset();
Check(hasherTest.Digest(), Convert.FromHexString("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
Console.WriteLine($"cases={cases}");
Console.WriteLine($"splits={splits}");
Console.WriteLine($"bcl_sha3_supported={System.Security.Cryptography.SHA3_256.IsSupported}");

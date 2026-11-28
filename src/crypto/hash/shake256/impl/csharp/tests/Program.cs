using System;
using Abc.Cryptography;

static void Check(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected)
{
    if (!actual.SequenceEqual(expected))
        throw new InvalidOperationException("SHAKE256 mismatch");
}

int cases = 0;
int splits = 0;
int[] outputChunks = [0, 1, 134, 1, 136, 137];
while (Console.ReadLine() is string line)
{
    string[] row = line.Split(':');
    byte[] message = Convert.FromHexString(row[0]);
    byte[] expected = Convert.FromHexString(row[2]);
    Check(Shake256.HashData(message, expected.Length), expected);
    for (int split = 0; split <= message.Length; split++)
    {
        var absorber = new Shake256();
        absorber.Update(message.AsSpan(0, split));
        absorber.Update(ReadOnlySpan<byte>.Empty);
        absorber.Update(message.AsSpan(split));
        KeccakSponge.Reader reader = absorber.Finish();
        KeccakSponge.Reader other = absorber.Finish();
        absorber.Reset();
        byte[] actual = new byte[409];
        int offset = 0;
        foreach (int count in outputChunks)
        {
            reader.ReadInto(actual.AsSpan(offset, count));
            offset += count;
        }
        Check(actual, expected);
        Check(other.Read(expected.Length), expected);
        splits++;
    }
    cases++;
}
byte[] input = [1, 2, 3];
byte[] before = Shake256.HashData(input, 200);
var absorberTest = new Shake256();
absorberTest.Update(input);
input.AsSpan().Clear();
var readerTest = absorberTest.Finish();
try
{
    readerTest.Read(-1);
    throw new InvalidOperationException("accepted negative output length");
}
catch (ArgumentOutOfRangeException)
{
    Check(readerTest.Read(200), before);
}
Console.WriteLine($"cases={cases}");
Console.WriteLine($"splits={splits}");

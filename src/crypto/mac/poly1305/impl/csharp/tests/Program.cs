using System;
using System.Collections.Generic;
using System.Text.Json;
using Abc.Cryptography;
using static TestSupport;

var outputs = new List<string>();
using var fixtures = Parse(args[0]);
foreach (var fixture in fixtures.RootElement.EnumerateArray())
{
    byte[] key = Field(fixture, "key");
    byte[] message = Field(fixture, "message");
    byte[] expected = Field(fixture, "expected");
    byte[] tag = new byte[17];
    tag[16] = 0xa9;
    Poly1305Mac.Authenticate(key, message, tag);
    Equal(tag.AsSpan(0, 16), expected, "One-shot tag");
    Require(tag[16] == 0xa9, "Tag wrote past 16 bytes.");

    // Exercise every split of the official vectors and public block boundaries on all other fixtures.
    int step = outputs.Count < 8 ? 1 : 16;
    for (int split = 0; split <= message.Length; split += step)
    {
        using var mac = new Poly1305Mac(key);
        mac.Update(message.AsSpan(0, split));
        mac.Update(ReadOnlySpan<byte>.Empty);
        mac.Update(message.AsSpan(split));
        mac.Finish(tag);
        Equal(tag.AsSpan(0, 16), expected, "Split update");
    }
    outputs.Add(Wire(tag.AsSpan(0, 16)));
}

Throws<ArgumentException>(() => new Poly1305Mac(new byte[31]));
using (var mac = new Poly1305Mac(new byte[32]))
{
    byte[] shortTag = new byte[15];
    shortTag.AsSpan().Fill(0xa9);
    byte[] snapshot = (byte[])shortTag.Clone();
    mac.Update(new byte[17]);
    Throws<ArgumentException>(() => mac.Finish(shortTag));
    Equal(shortTag, snapshot, "Rejected tag write reached destination.");
    byte[] tag = new byte[16];
    mac.Finish(tag);
    Equal(tag, new byte[16], "Short output retry");
    Throws<ObjectDisposedException>(() => mac.Finish(tag));
    Throws<ObjectDisposedException>(() => mac.Update(new byte[1]));
}
Console.WriteLine(JsonSerializer.Serialize(new { boundaries = "passed", outputs }));

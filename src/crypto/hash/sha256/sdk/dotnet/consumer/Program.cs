using Abc.Cryptography;
using System.Security.Cryptography;

static void Require(bool condition, string detail)
{
    if (!condition) throw new InvalidOperationException(detail);
}

static void RequiresException<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}");
}

Require(Sha256.Implementation == "sha256-abc-rust-portable", "provider identity");
Require(Convert.ToHexString(Sha256.Digest("abc"u8)).ToLowerInvariant() ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "NIST known answer");

byte[] input = Enumerable.Range(0, 120).Select(value => (byte)value).ToArray();
using var context = new Sha256Stream();
context.Update(input.AsSpan(0, 56));
context.Update(input.AsSpan(56));
Require(context.Finish().SequenceEqual(SHA256.HashData(input)), "streaming digest");
RequiresException<InvalidOperationException>(() => context.Finish());
context.Reset();
Require(context.Finish().SequenceEqual(SHA256.HashData([])), "empty digest after reset");
context.Dispose();
RequiresException<ObjectDisposedException>(() => context.Update([]));
Console.WriteLine("External .NET SHA-256 consumer passed");

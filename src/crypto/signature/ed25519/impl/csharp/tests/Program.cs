using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using Abc.Cryptography;

static byte[] Hex(string value) => Convert.FromHexString(value);

static void Require(bool result, string failure)
{
    if (!result) throw new InvalidOperationException(failure);
}

static void Reject(Action operation)
{
    try { operation(); }
    catch (ArgumentException) { return; }
    throw new InvalidOperationException("Invalid Ed25519 seed width accepted");
}

static byte[] SignBit(byte[] point)
{
    var result = (byte[])point.Clone();
    result[31] ^= 128;
    return result;
}

byte[] seed = SHA256.HashData([1, 2, 3]);
byte[] message = [1, 0, 2, 31];
byte[] pub = Ed25519.PublicKey(seed);
byte[] signature = Ed25519.Sign(seed, message);
Require(Ed25519.Verify(pub, message, signature), "Generated Ed25519 signature failed");
Require(!Ed25519.Verify(pub, [1], signature), "Ed25519 accepted the wrong message");
Require(!Ed25519.Verify(Ed25519.PublicKey(new byte[32]), message, signature), "Accepted wrong public key");
byte[] order = Hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
byte[] altered = (byte[])signature.Clone();
order.CopyTo(altered, 32);
Require(!Ed25519.Verify(pub, message, altered), "Accepted S equal to the group order");
var orderNumber = new BigInteger(order, true, false);
var added = (orderNumber + new BigInteger(signature.AsSpan(32), true, false)).ToByteArray(true, false);
altered.AsSpan(32).Clear();
added.CopyTo(altered, 32);
Require(!Ed25519.Verify(pub, message, altered), "Accepted a scalar with the group order added");
foreach (int width in new[] { 0, 31, 33 })
{
    Reject(() => Ed25519.PublicKey(new byte[width]));
    Reject(() => Ed25519.Sign(new byte[width], message));
    Require(!Ed25519.Verify(new byte[width], message, signature), "Bad public key width accepted");
}
Require(!Ed25519.Verify(pub, message, new byte[63]), "Accepted truncated Ed25519 signature");
Require(!Ed25519.Verify(pub, message, new byte[65]), "Accepted extended Ed25519 signature");

byte[] zero = new byte[32];
byte[] identity = new byte[32];
identity[0] = 1;
byte[] offCurve = new byte[32];
offCurve[0] = 2;
byte[] minusOne = Hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
byte[] largerY = Hex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
byte[] order8A = Hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
byte[] order8B = Hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
byte[][] invalidPoints = [zero, SignBit(zero), identity, minusOne, order8A, SignBit(order8A), order8B,
                          SignBit(order8B), SignBit(identity), SignBit(minusOne), offCurve, largerY];
foreach (var invalid in invalidPoints)
{
    Require(!Ed25519.Verify(invalid, message, signature), "Accepted an invalid A encoding");
    invalid.CopyTo(altered, 0);
    signature.AsSpan(32).CopyTo(altered.AsSpan(32));
    Require(!Ed25519.Verify(pub, message, altered), "Accepted an invalid R encoding");
}

byte[] generator = Hex("5866666666666666666666666666666666666666666666666666666666666666");
byte[] forged = new byte[64];
generator.CopyTo(forged, 0);
forged[32] = 1;
Require(!Ed25519.Verify(identity, message, forged), "Identity verification key passed the strict check");
Array.Clear(forged);
identity.CopyTo(forged, 0);
byte[] hash = SHA512.HashData([..identity, ..generator, ..message]);
((new BigInteger(hash, true, false)) % orderNumber).ToByteArray(true, false).CopyTo(forged, 32);
Require(!Ed25519.Verify(generator, message, forged), "Identity signature point passed the strict check");

int cases = 0;
for (string? line; (line = Console.ReadLine()) != null; cases++)
{
    string[] row = line.Split(':');
    byte[] privateSeed = Hex(row[0]);
    var msg = Hex(row[1]);
    var key = Hex(row[2]);
    var sig = Hex(row[3]);
    Require(Ed25519.PublicKey(privateSeed).SequenceEqual(key), "Ed25519 oracle public key mismatch");
    Require(Ed25519.Sign(privateSeed, msg).SequenceEqual(sig), "Ed25519 oracle signature mismatch");
    Require(Ed25519.Verify(key, msg, sig), "Independent Ed25519 signature failed");
    Require(Hex(row[0]).SequenceEqual(privateSeed), "Ed25519 mutated the caller's seed");
}
Console.WriteLine(JsonSerializer.Serialize(new { cases, rfc_known_answers = 3, invalid_points = invalidPoints.Length,
    strict_identity_rejections = 2 }));

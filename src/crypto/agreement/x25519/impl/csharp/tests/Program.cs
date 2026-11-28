using System.Text.Json;
using Abc.Cryptography;

static byte[] Hex(string value) => Convert.FromHexString(value);

static void Same(byte[] expected, byte[]? actual)
{
    if (actual is null || !actual.SequenceEqual(expected))
        throw new InvalidOperationException("X25519 output mismatch");
}

static void Reject(Action operation)
{
    try { operation(); }
    catch (ArgumentException) { return; }
    throw new InvalidOperationException("Invalid X25519 width accepted");
}

byte[] alice = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
byte[] bob = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
byte[] alicePublic = Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
byte[] bobPublic = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
byte[] shared = Hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
Same(alicePublic, X25519.PublicKey(alice));
Same(bobPublic, X25519.PublicKey(bob));
Same(shared, X25519.SharedSecret(alice, bobPublic));
Same(shared, X25519.SharedSecret(bob, alicePublic));

byte[] scalar = new byte[32];
scalar[0] = 9;
byte[] point = scalar;
for (int i = 1; i <= 1000; i++)
{
    var next = X25519.SharedSecret(scalar, point) ?? throw new InvalidOperationException("RFC iteration rejected");
    point = scalar;
    scalar = next;
    if (i == 1)
        Same(Hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), scalar);
}
Same(Hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), scalar);

string[] lowOrder = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
};
foreach (string wire in lowOrder)
{
    var encoding = Hex(wire);
    if (X25519.SharedSecret(alice, encoding) != null) throw new InvalidOperationException("Low-order point accepted");
    encoding[31] |= 128;
    if (X25519.SharedSecret(alice, encoding) != null) throw new InvalidOperationException("Low-order alias accepted");
}
foreach (int width in new[] { 0, 31, 33, 56 })
{
    Reject(() => X25519.PublicKey(new byte[width]));
    Reject(() => X25519.SharedSecret(new byte[width], alicePublic));
    Reject(() => X25519.SharedSecret(alice, new byte[width]));
}

int cases = 0;
for (string? line; (line = Console.ReadLine()) != null; cases++)
{
    string[] row = line.Split(':');
    byte[] seed = Hex(row[0]);
    byte[] peer = Hex(row[1]);
    Same(Hex(row[2]), X25519.PublicKey(seed));
    Same(Hex(row[3]), X25519.SharedSecret(seed, peer));
    Same(Hex(row[0]), seed);
    Same(Hex(row[1]), peer);
}
Console.WriteLine(JsonSerializer.Serialize(new { cases, rfc_known_answers = 6, low_order_rejections = 14 }));

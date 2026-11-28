using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Abc.Cryptography;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using BcInteger = Org.BouncyCastle.Math.BigInteger;

static byte[] Hex(string value) => Convert.FromHexString(value);
static string Wire(byte[] value) => Convert.ToHexStringLower(value);

static void Require(bool condition, string failure)
{
    if (!condition) throw new InvalidOperationException(failure);
}

static void Reject(Action operation)
{
    try { operation(); }
    catch (ArgumentException) { return; }
    throw new InvalidOperationException("Accepted invalid scalar");
}

static IDsaKCalculator NonceCalculator()
{
    var type = typeof(EcdsaP256Sha256).GetNestedType("Rfc6979Nonce", BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("Missing RFC 6979 calculator in packaged SDK");
    return (IDsaKCalculator)(Activator.CreateInstance(type, nonPublic: true)
        ?? throw new InvalidOperationException("Could not construct packaged RFC 6979 calculator"));
}

static void Retry(byte[] scalar)
{
    var parameters = new ECDomainParameters(CustomNamedCurves.GetByName("secp256r1"));
    var nonce = NonceCalculator();
    using var cleanup = (IDisposable)nonce;
    var d = new BcInteger(1, scalar);
    nonce.Init(parameters.N, d, SHA256.HashData("sample"u8));
    Require(Wire(nonce.NextK().ToByteArrayUnsigned()) ==
        "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60", "RFC6979 first candidate mismatch");
    // Independently computed with the RFC 6979 HMAC-SHA-256 transcript, including h.3.
    Require(Wire(nonce.NextK().ToByteArrayUnsigned()) ==
        "8e83dc490bc5fc4d5992bd63cd87f254adffcb930f8a8011702a88870f638fdb", "RFC6979 retry state mismatch");
    nonce.Init(parameters.N, d, parameters.N.ToByteArrayUnsigned());
    var reduced = nonce.NextK();
    nonce.Init(parameters.N, d, new byte[32]);
    Require(reduced.Equals(nonce.NextK()), "bits2octets did not reduce by the P-256 order");

    // Inject k=1 only into the first provider call. With d=1 and e=n-x(G)
    // the first S is zero. The decorator still consumes the first RFC nonce
    // and delegates the next call to the packaged calculator's retry path.
    byte[] digest = Hex("94e82e0c1ed3bdb90743191a9c5bbf0d45e37d2c792c6ae3ff18917d23ca62bb");
    Require(new BcInteger(1, digest).Add(parameters.G.Normalize().AffineXCoord.ToBigInteger())
        .Mod(parameters.N).SignValue == 0, "Synthetic first candidate would not produce S=0");
    var force = new FirstUnusableNonce(nonce);
    var signer = new ECDsaSigner(force);
    signer.Init(true, new ECPrivateKeyParameters(BcInteger.One, parameters));
    var produced = signer.GenerateSignature(digest);
    Require(force.Calls == 2 && force.LastActual is not null &&
        Wire(force.LastActual.ToByteArrayUnsigned()) ==
        "c3956be83b48aae6761c2f77e98320c67fb9593fcdc307b59d788c75ed68b54a", "Provider did not retry with RFC6979 h.3");
    var verifier = new ECDsaSigner();
    verifier.Init(false, new ECPublicKeyParameters(parameters.G, parameters));
    Require(verifier.VerifySignature(digest, produced[0], produced[1]), "Retried ECDSA signature did not verify");
}

if (args[0] == "sign")
{
    var order = Hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    var scalar = Hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    Retry(scalar);
    var point = EcdsaP256Sha256.PublicKey(scalar);
    Require(Wire(point) == "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", "RFC public key mismatch");
    var compressed = point[..33];
    compressed[0] = 3;
    var rfc = new (string Message, string Signature)[] {
        ("sample", "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
                   "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"),
        ("test", "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" +
                 "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"),
    };
    foreach (var (name, expected) in rfc)
    {
        byte[] message = Encoding.ASCII.GetBytes(name);
        byte[] sig = EcdsaP256Sha256.Sign(scalar, message);
        Require(Wire(sig) == expected, "RFC6979 signature mismatch");
        Require(EcdsaP256Sha256.Verify(compressed, message, sig), "Compressed SEC1 point was rejected");
        Require(EcdsaP256Sha256.Verify(point, message, sig), "Uncompressed SEC1 point was rejected");
        var other = new BigInteger(order, true, true) - new BigInteger(sig.AsSpan(32), true, true);
        var encoded = other.ToByteArray(true, true);
        var alternate = (byte[])sig.Clone();
        alternate.AsSpan(32).Clear();
        encoded.CopyTo(alternate, 64 - encoded.Length);
        Require(EcdsaP256Sha256.Verify(point, message, alternate), "Alternate S value was rejected");
    }
    byte[] ones = Enumerable.Repeat((byte)255, 32).ToArray();
    foreach (byte[] bad in new[] { new byte[31], new byte[33], new byte[32], order, ones })
    {
        Reject(() => EcdsaP256Sha256.PublicKey(bad));
        Reject(() => EcdsaP256Sha256.Sign(bad, []));
    }
    var testSignature = EcdsaP256Sha256.Sign(scalar, []);
    var hybrid = (byte[])point.Clone();
    hybrid[0] = 7;
    byte[] offCurve = new byte[65];
    offCurve[0] = 4;
    byte[] abovePrime = [2, ..ones];
    foreach (byte[] bad in new[] { new byte[0], new byte[1], point[..64], hybrid, offCurve, abovePrime })
        Require(!EcdsaP256Sha256.Verify(bad, [], testSignature), "Accepted an invalid point");
    foreach (int offset in new[] { 0, 32 })
    {
        byte[] present = (byte[])testSignature.Clone();
        present.AsSpan(offset, 32).Clear();
        Require(!EcdsaP256Sha256.Verify(point, [], present), "Accepted zero signature component");
        order.CopyTo(present, offset);
        Require(!EcdsaP256Sha256.Verify(point, [], present), "Accepted component equal to the order");
    }
    Require(!EcdsaP256Sha256.Verify(point, [], testSignature[..63]), "Accepted short signature");
    Require(!EcdsaP256Sha256.Verify(point, [], [..testSignature, 0]), "Accepted long signature");
    Require(!EcdsaP256Sha256.Verify(point, [1], testSignature), "Accepted wrong message");
}

int cases = 0;
for (string? line; (line = Console.ReadLine()) != null; cases++)
{
    string[] row = line.Split(':');
    if (args[0] == "sign")
    {
        var scalar = Hex(row[0]);
        var message = Hex(row[1]);
        var sig = EcdsaP256Sha256.Sign(scalar, message);
        Require(sig.SequenceEqual(EcdsaP256Sha256.Sign(scalar, message)), "Nondeterministic signing");
        Console.WriteLine($"{Wire(EcdsaP256Sha256.PublicKey(scalar))}:{Wire(sig)}");
    }
    else
    {
        var message = Hex(row[0]);
        var sig = Hex(row[3]);
        Require(EcdsaP256Sha256.Verify(Hex(row[1]), message, sig), "OpenSSL uncompressed verification failed");
        Require(EcdsaP256Sha256.Verify(Hex(row[2]), message, sig), "OpenSSL compressed verification failed");
    }
}
if (args[0] != "sign") Console.WriteLine(cases);

sealed class FirstUnusableNonce(IDsaKCalculator calculator) : IDsaKCalculator
{
    public bool IsDeterministic => true;
    public int Calls { get; private set; }
    public BcInteger? LastActual { get; private set; }

    public void Init(BcInteger n, SecureRandom random) => calculator.Init(n, random);
    public void Init(BcInteger n, BcInteger d, byte[] digest)
    {
        Calls = 0;
        LastActual = null;
        calculator.Init(n, d, digest);
    }

    public BcInteger NextK()
    {
        LastActual = calculator.NextK();
        return ++Calls == 1 ? BcInteger.One : LastActual;
    }
}

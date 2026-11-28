using System.Security.Cryptography;
using Abc.Cryptography;

static byte[] Hex(string value) => Convert.FromHexString(value);
static string Wire(byte[] value) => Convert.ToHexStringLower(value);

static void Require(bool result, string failure)
{
    if (!result) throw new InvalidOperationException(failure);
}

static void Reject(Action operation)
{
    try { operation(); }
    catch (ArgumentException) { return; }
    throw new InvalidOperationException("ML-DSA-65 accepted malformed input");
}

if (args[0] == "acvp")
{
    byte[] seed = SHA256.HashData([1, 2, 3]);
    byte[] publicKey = MlDsa65.PublicKey(seed);
    byte[] signature = MlDsa65.Sign(seed, [], []);
    Require(MlDsa65.Verify(publicKey, [], signature, []), "Empty ML-DSA-65 input rejected");
    Require(!MlDsa65.Verify(publicKey, [], signature, new byte[256]), "Oversized context accepted");
    Require(!MlDsa65.Verify(publicKey, [], new byte[3308]), "Truncated signature accepted");
    Require(!MlDsa65.Verify(publicKey, [], new byte[3310]), "Extended signature accepted");
    Require(!MlDsa65.Verify(new byte[1951], [], signature), "Truncated public key accepted");
    Require(!MlDsa65.Verify(new byte[1953], [], signature), "Extended public key accepted");
    Reject(() => MlDsa65.Sign(seed, [], new byte[256]));
    Reject(() => MlDsa65.PublicKey(new byte[4032]));

    const int offset = 3248;
    const int omega = 55;
    var full = new byte[3309];
    Array.Fill(full, (byte)omega, offset + omega, 6);
    for (int i = 0; i < omega; i++) full[offset + i] = (byte)i;
    byte[] backwards = (byte[])full.Clone();
    backwards[^1] = 54;
    byte[] oversized = (byte[])full.Clone();
    oversized[^1] = 56;
    byte[] duplicate = (byte[])full.Clone();
    duplicate[offset + 1] = duplicate[offset];
    byte[] unordered = (byte[])full.Clone();
    unordered[offset] = 2;
    byte[] nonzeroTail = new byte[3309];
    nonzeroTail[offset + omega - 1] = 1;
    foreach (byte[] malformed in new[] { backwards, oversized, duplicate, unordered, nonzeroTail })
        Require(!MlDsa65.Verify(publicKey, [], malformed), "Malformed ML-DSA-65 hint shape accepted");
}

int count = 0;
for (string? line; (line = Console.ReadLine()) != null; count++)
{
    string[] row = line.Split(':');
    switch (args[0])
    {
        case "acvp":
            switch (row[0])
            {
                case "keygen":
                    byte[] pub = MlDsa65.PublicKey(Hex(row[1]));
                    Require(Wire(SHA256.HashData(pub)) == row[2], "ACVP public-key digest mismatch");
                    break;
                case "expanded-sign":
                    Require(MlDsa65.Verify(Hex(row[2]), Hex(row[3]), Hex(row[5]), Hex(row[4])),
                        "ACVP deterministic signature was rejected");
                    break;
                case "verify":
                    Require(MlDsa65.Verify(Hex(row[1]), Hex(row[2]), Hex(row[4]), Hex(row[3])) ==
                        bool.Parse(row[5]), "ACVP verification outcome mismatch");
                    break;
                default:
                    throw new InvalidOperationException("Unknown ACVP operation");
            }
            break;
        case "sign":
            byte[] seed = Hex(row[0]);
            byte[] message = Hex(row[1]);
            byte[] ctx = Hex(row[2]);
            byte[] publicKey = MlDsa65.PublicKey(seed);
            byte[] signature = MlDsa65.Sign(seed, message, ctx);
            Require(Hex(row[0]).SequenceEqual(seed), "ML-DSA-65 changed the caller's seed");
            Require(signature.SequenceEqual(MlDsa65.Sign(seed, message, ctx)), "Nondeterministic signing");
            Require(MlDsa65.Verify(publicKey, message, signature, ctx), "Generated signature rejected");
            Require(!MlDsa65.Verify(publicKey, message, signature, ctx.Length == 0 ? [0] : []),
                "Wrong binary context verified");
            Console.WriteLine($"{Wire(publicKey)}:{Wire(signature)}");
            break;
        case "verify":
            Require(MlDsa65.Verify(Hex(row[0]), Hex(row[1]), Hex(row[3]), Hex(row[2])),
                "OpenSSL ML-DSA-65 signature rejected");
            break;
        default:
            throw new InvalidOperationException("Unknown consumer operation");
    }
}
if (args[0] != "sign") Console.WriteLine(count);

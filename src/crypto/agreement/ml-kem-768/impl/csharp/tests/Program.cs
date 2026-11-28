using System.Security.Cryptography;
using Abc.Cryptography;

static byte[] Hex(string value) => Convert.FromHexString(value);
static string Wire(byte[] value) => Convert.ToHexStringLower(value);
static void Same(byte[] expected, byte[] computed)
{
    if (!expected.SequenceEqual(computed)) throw new InvalidOperationException("ML-KEM-768 mismatch");
}
static void Reject(Action operation)
{
    try { operation(); }
    catch (ArgumentException) { return; }
    throw new InvalidOperationException("ML-KEM-768 accepted malformed input");
}

if (args[0] == "acvp")
{
    Reject(() => MlKem768.PublicKey(new byte[63]));
    Reject(() => MlKem768.PublicKey(new byte[65]));
    Reject(() => MlKem768.Encapsulate(new byte[1183]));
    Reject(() => MlKem768.Encapsulate(new byte[1185]));
    Reject(() => MlKem768.Decapsulate(new byte[64], new byte[1087]));
    Reject(() => MlKem768.Decapsulate(new byte[64], new byte[1089]));
    for (int i = 0; i < 4; i++)
    {
        byte[] seed = RandomNumberGenerator.GetBytes(64);
        byte[] pub = MlKem768.PublicKey(seed);
        var (ciphertext, shared) = MlKem768.Encapsulate(pub);
        Same(shared, MlKem768.Decapsulate(seed, ciphertext));
        var noncanonical = (byte[])pub.Clone();
        noncanonical[0] = 1;
        noncanonical[1] = (byte)((noncanonical[1] & 0xf0) | 13);
        Reject(() => MlKem768.Encapsulate(noncanonical));
        var invalidSecond = (byte[])pub.Clone();
        invalidSecond[1] = (byte)((invalidSecond[1] & 15) | 16);
        invalidSecond[2] = 0xd0;
        Reject(() => MlKem768.Encapsulate(invalidSecond));
    }
}

int count = 0;
for (string? line; (line = Console.ReadLine()) != null; count++)
{
    string[] row = line.Split(':');
    switch (args[0])
    {
        case "acvp":
            if (row[0] == "keygen")
                Same(Hex(row[2]), MlKem768.PublicKey(Hex(row[1])));
            else if (row[0] == "reject_ek")
                Reject(() => MlKem768.Encapsulate(Hex(row[1])));
            else
                throw new InvalidOperationException("Unexpected ACVP operation");
            break;
        case "encapsulate":
            byte[] seed = Hex(row[0]);
            byte[] pub = MlKem768.PublicKey(seed);
            var (ciphertext, secret) = MlKem768.Encapsulate(pub);
            Same(secret, MlKem768.Decapsulate(seed, ciphertext));
            Same(Hex(row[0]), seed);
            Console.WriteLine($"{Wire(pub)}:{Wire(ciphertext)}:{Wire(secret)}");
            break;
        case "decapsulate":
            Same(Hex(row[2]), MlKem768.Decapsulate(Hex(row[0]), Hex(row[1])));
            break;
        default:
            throw new InvalidOperationException("Unknown ML-KEM-768 consumer operation");
    }
}
if (args[0] != "encapsulate") Console.WriteLine(count);

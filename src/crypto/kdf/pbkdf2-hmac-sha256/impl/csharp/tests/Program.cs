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

static void Check(byte[] password, byte[] salt, int rounds, byte[] expected)
{
    var output = new byte[expected.Length];
    Require(Pbkdf2Sha256.Derive(password, salt, (uint)rounds, output) == Pbkdf2Status.Success &&
        output.AsSpan().SequenceEqual(expected), "PBKDF2 output");
}

Check(Encoding.ASCII.GetBytes("passwd"), Encoding.ASCII.GetBytes("salt"), 1, Convert.FromHexString(
    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
    "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
Check(Encoding.ASCII.GetBytes("Password"), Encoding.ASCII.GetBytes("NaCl"), 80000, Convert.FromHexString(
    "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" +
    "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"));

var random = new Random(8018);
int comparisons = 0;
foreach (int size in new[] {1, 31, 32, 33, 63, 64, 65, 95, 257})
{
    foreach (int passwordSize in new[] {0, 1, 64, 65, 4096})
    {
        var password = new byte[passwordSize];
        var salt = new byte[size % 97];
        random.NextBytes(password);
        random.NextBytes(salt);
        int rounds = size % 17 + 1;
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(password, salt, rounds, HashAlgorithmName.SHA256, size);
        Check(password, salt, rounds, expected);
        var overlap = new byte[Math.Max(passwordSize, size)];
        password.CopyTo(overlap, 0);
        Require(Pbkdf2Sha256.Derive(overlap.AsSpan(0, passwordSize), salt, (uint)rounds,
            overlap.AsSpan(0, size)) == Pbkdf2Status.Success &&
            overlap.AsSpan(0, size).SequenceEqual(expected), "password overlap");
        ++comparisons;
    }
}
byte[] sentinel = Enumerable.Repeat((byte)0xa5, 16).ToArray();
Require(Pbkdf2Sha256.Derive([], [], 0, sentinel) == Pbkdf2Status.InvalidIterations, "zero rounds");
Require(Pbkdf2Sha256.Derive([], [], 1, []) == Pbkdf2Status.InvalidOutputLength, "empty output");
Require(Pbkdf2Sha256.Derive([], sentinel, 1, sentinel) == Pbkdf2Status.SaltOverlapsOutput, "overlap");
Require(sentinel.All(value => value == 0xa5), "rejection changed output");
Console.WriteLine($"{{\"known_answers\":2,\"comparisons\":{comparisons},\"rejection_atomicity\":true}}");

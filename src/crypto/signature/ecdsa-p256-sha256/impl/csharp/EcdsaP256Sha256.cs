using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Integer = Org.BouncyCastle.Math.BigInteger;

namespace Abc.Cryptography;

public static class EcdsaP256Sha256
{
    private static readonly ECDomainParameters Domain = new(CustomNamedCurves.GetByName("secp256r1"));

    private static Integer ParsePrivate(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new ArgumentException("P-256 requires a 32-byte scalar", nameof(key));
        var scalar = new Integer(1, key);
        if (scalar.SignValue < 1 || scalar.CompareTo(Domain.N) >= 0)
            throw new ArgumentException("Invalid P-256 scalar", nameof(key));
        return scalar;
    }

    public static byte[] PublicKey(ReadOnlySpan<byte> key) =>
        new Org.BouncyCastle.Math.EC.Multiplier.FixedPointCombMultiplier()
            .Multiply(Domain.G, ParsePrivate(key)).GetEncoded(false);

    public static byte[] Sign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        using var nonce = new Rfc6979Nonce();
        var signer = new ECDsaSigner(nonce);
        signer.Init(true, new ECPrivateKeyParameters(ParsePrivate(key), Domain));
        var values = signer.GenerateSignature(SHA256.HashData(message));
        var output = new byte[64];
        for (int i = 0; i < 2; i++)
        {
            byte[] encoded = values[i].ToByteArrayUnsigned();
            encoded.CopyTo(output, (i + 1) * 32 - encoded.Length);
        }
        return output;
    }

    public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != 64
            || !((key.Length == 33 && key[0] is 2 or 3) || (key.Length == 65 && key[0] == 4))) return false;
        var r = new Integer(1, signature[..32]);
        var s = new Integer(1, signature[32..]);
        if (r.SignValue < 1 || r.CompareTo(Domain.N) >= 0 || s.SignValue < 1 || s.CompareTo(Domain.N) >= 0)
            return false;
        try
        {
            var point = Domain.Curve.DecodePoint(key.ToArray());
            var verifier = new ECDsaSigner();
            verifier.Init(false, new ECPublicKeyParameters(point, Domain));
            return verifier.VerifySignature(SHA256.HashData(message), r, s);
        }
        catch (ArgumentException) { return false; }
    }

    private sealed class Rfc6979Nonce : IDsaKCalculator, IDisposable
    {
        private const int WordBytes = 32;
        private readonly byte[] key = new byte[WordBytes];
        private readonly byte[] value = new byte[WordBytes];
        private Integer? order;
        private bool returned;

        public bool IsDeterministic => true;

        public void Init(Integer n, SecureRandom random) =>
            throw new InvalidOperationException("RFC 6979 requires a private scalar and digest");

        public void Init(Integer n, Integer d, byte[] digest)
        {
            if (!n.Equals(Domain.N) || digest.Length != WordBytes)
                throw new ArgumentException("The RFC 6979 adapter requires the P-256 order and a SHA-256 digest");

            order = n;
            returned = false;
            CryptographicOperations.ZeroMemory(key);
            Array.Fill(value, (byte)1);
            Span<byte> input = stackalloc byte[3 * WordBytes + 1];
            input.Clear();
            try
            {
                WriteScalar(d, input.Slice(WordBytes + 1, WordBytes));
                var digestValue = new Integer(1, digest);
                if (digestValue.CompareTo(n) >= 0)
                    digestValue = digestValue.Subtract(n);
                WriteScalar(digestValue, input[(2 * WordBytes + 1)..]);

                value.AsSpan().CopyTo(input);
                Update(input, key);
                Update(value, value);
                value.AsSpan().CopyTo(input);
                input[WordBytes] = 1;
                Update(input, key);
                Update(value, value);
            }
            finally { CryptographicOperations.ZeroMemory(input); }
        }

        public Integer NextK()
        {
            Integer n = order ?? throw new InvalidOperationException("RFC 6979 nonce state is uninitialized");
            // ECDsaSigner requests k again only after it rejected the previously returned signature candidate.
            if (returned) RejectCandidate();
            while (true)
            {
                Update(value, value);
                var candidate = new Integer(1, value);
                if (candidate.SignValue > 0 && candidate.CompareTo(n) < 0)
                {
                    returned = true;
                    return candidate;
                }
                RejectCandidate();
            }
        }

        private void RejectCandidate()
        {
            Span<byte> input = stackalloc byte[WordBytes + 1];
            try
            {
                value.AsSpan().CopyTo(input);
                input[WordBytes] = 0;
                Update(input, key);
                Update(value, value);
            }
            finally { CryptographicOperations.ZeroMemory(input); }
        }

        private void Update(ReadOnlySpan<byte> input, Span<byte> destination)
        {
            Span<byte> mac = stackalloc byte[WordBytes];
            try
            {
                HMACSHA256.HashData(key, input, mac);
                mac.CopyTo(destination);
            }
            finally { CryptographicOperations.ZeroMemory(mac); }
        }

        private static void WriteScalar(Integer scalar, Span<byte> output)
        {
            byte[] encoded = scalar.ToByteArrayUnsigned();
            try { encoded.AsSpan().CopyTo(output[^encoded.Length..]); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(value);
            order = null;
        }
    }
}

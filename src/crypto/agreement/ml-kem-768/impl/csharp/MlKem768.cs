using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace Abc.Cryptography;

public static class MlKem768
{
    private static readonly MLKemParameters Parameters = MLKemParameters.ml_kem_768;

    public static byte[] PublicKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 64) throw new ArgumentException("ML-KEM-768 requires a 64-byte seed", nameof(seed));
        var material = seed.ToArray();
        try { return MLKemPrivateKeyParameters.FromSeed(Parameters, material).GetPublicKeyEncoded(); }
        finally { CryptographicOperations.ZeroMemory(material); }
    }

    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != 1184) throw new ArgumentException("Invalid ML-KEM-768 public-key length", nameof(encoded));
        byte[] wire = encoded.ToArray();
        for (int i = 0; i < 1152; i += 3)
        {
            int a = wire[i] | (wire[i + 1] & 15) << 8;
            int b = wire[i + 1] >> 4 | wire[i + 2] << 4;
            if (a >= 3329 || b >= 3329)
                throw new ArgumentException("Noncanonical ML-KEM-768 public key", nameof(encoded));
        }
        var encapsulator = new MLKemEncapsulator(Parameters);
        encapsulator.Init(MLKemPublicKeyParameters.FromEncoding(Parameters, wire));
        var ciphertext = new byte[1088];
        var secret = new byte[32];
        encapsulator.Encapsulate(ciphertext, secret);
        return (ciphertext, secret);
    }

    public static byte[] Decapsulate(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> ciphertext)
    {
        if (seed.Length != 64 || ciphertext.Length != 1088) throw new ArgumentException("Invalid ML-KEM-768 input length");
        var material = seed.ToArray();
        try
        {
            var decapsulator = new MLKemDecapsulator(Parameters);
            decapsulator.Init(MLKemPrivateKeyParameters.FromSeed(Parameters, material));
            var secret = new byte[32];
            decapsulator.Decapsulate(ciphertext, secret);
            return secret;
        }
        finally { CryptographicOperations.ZeroMemory(material); }
    }
}

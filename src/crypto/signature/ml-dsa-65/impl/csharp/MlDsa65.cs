using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Abc.Cryptography;

public static class MlDsa65
{
    private static readonly MLDsaParameters Parameters = MLDsaParameters.ml_dsa_65;

    public static byte[] PublicKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 32) throw new ArgumentException("ML-DSA-65 requires a 32-byte seed", nameof(seed));
        byte[] copy = seed.ToArray();
        try { return MLDsaPrivateKeyParameters.FromSeed(Parameters, copy).GetPublicKeyEncoded(); }
        finally { CryptographicOperations.ZeroMemory(copy); }
    }

    public static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context = default)
    {
        if (seed.Length != 32 || context.Length > 255) throw new ArgumentException("Invalid ML-DSA-65 seed or context length");
        byte[] copy = seed.ToArray();
        try
        {
            var signer = new MLDsaSigner(Parameters, deterministic: true);
            var key = MLDsaPrivateKeyParameters.FromSeed(Parameters, copy);
            signer.Init(true, new ParametersWithContext(key, context));
            signer.BlockUpdate(message);
            return signer.GenerateSignature();
        }
        finally { CryptographicOperations.ZeroMemory(copy); }
    }

    public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context = default)
    {
        if (key.Length != 1952 || signature.Length != 3309 || context.Length > 255) return false;
        var verifier = new MLDsaSigner(Parameters, deterministic: true);
        try
        {
            verifier.Init(false, new ParametersWithContext(MLDsaPublicKeyParameters.FromEncoding(Parameters, key.ToArray()), context));
            verifier.BlockUpdate(message);
            return verifier.VerifySignature(signature.ToArray());
        }
        catch (ArgumentException) { return false; }
    }
}

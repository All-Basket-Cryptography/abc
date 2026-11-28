using System.Security.Cryptography;
using Provider = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace Abc.Cryptography;

public static class X25519
{
    public static byte[] PublicKey(ReadOnlySpan<byte> secret)
    {
        if (secret.Length != 32) throw new ArgumentException("X25519 requires 32 bytes", nameof(secret));
        var output = new byte[32];
        Provider.GeneratePublicKey(secret, output);
        return output;
    }

    public static byte[]? SharedSecret(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> peer)
    {
        if (secret.Length != 32 || peer.Length != 32) throw new ArgumentException("X25519 requires 32-byte inputs");
        Span<byte> encoded = stackalloc byte[32];
        peer.CopyTo(encoded);
        encoded[31] &= 127;
        bool high = encoded[31] == 127;
        for (int i = 1; i < 31; i++) high &= encoded[i] == 255;
        if (high && encoded[0] >= 237)
        {
            byte low = (byte)(encoded[0] - 237);
            encoded.Clear();
            encoded[0] = low;
        }
        var output = new byte[32];
        if (Provider.CalculateAgreement(secret, encoded, output)) return output;
        CryptographicOperations.ZeroMemory(output);
        return null;
    }
}

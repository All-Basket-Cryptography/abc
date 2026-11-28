using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Abc.Cryptography;

public static class Argon2id
{
    private static void Validate(int memoryKiB, int passes, int lanes)
    {
        if (lanes < 1 || lanes >= 1 << 24 || passes < 1 || memoryKiB < 8 * lanes)
            throw new ArgumentOutOfRangeException(nameof(memoryKiB), "Invalid RFC 9106 parameters");
    }

    public static long WorkspaceBytes(int memoryKiB, int lanes)
    {
        Validate(memoryKiB, 1, lanes);
        return RoundedBytes(memoryKiB, lanes);
    }

    private static long RoundedBytes(int memoryKiB, int lanes) =>
        (long)(memoryKiB / (4 * lanes)) * (4 * lanes) * 1024;

    public static byte[] Derive(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        int memoryKiB, int passes, int lanes, int length, long memoryLimit,
        ReadOnlySpan<byte> secret = default, ReadOnlySpan<byte> associatedData = default)
    {
        Validate(memoryKiB, passes, lanes);
        if (length < 4 || RoundedBytes(memoryKiB, lanes) + length > memoryLimit || salt.Length < 8)
            throw new ArgumentException("Invalid Argon2id output length, salt length or memory budget");

        var secretBytes = secret.ToArray();
        var passBytes = password.ToArray();
        var builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id);
        Argon2Parameters? parameters = null;
        try
        {
            parameters = builder.WithVersion(Argon2Parameters.Version13)
                .WithMemoryAsKB(memoryKiB).WithIterations(passes).WithParallelism(lanes)
                .WithSalt(salt.ToArray()).WithSecret(secretBytes).WithAdditional(associatedData.ToArray()).Build();
            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);
            var result = new byte[length];
            generator.GenerateBytes(passBytes, result);
            return result;
        }
        finally
        {
            parameters?.Clear();
            builder.Clear();
            CryptographicOperations.ZeroMemory(passBytes);
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }
}

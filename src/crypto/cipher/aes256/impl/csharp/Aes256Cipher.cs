using System;
using System.Security.Cryptography;

namespace Abc.Cryptography;

/// <summary>AES-256 block operations backed by the .NET AES provider.</summary>
public sealed class Aes256Cipher : IDisposable
{
    public const int KeySize = 32;
    public const int BlockSize = 16;

    private readonly ICryptoTransform encryptor;
    private readonly ICryptoTransform decryptor;
    private readonly byte[] inputBlock = new byte[BlockSize];
    private readonly byte[] outputBlock = new byte[BlockSize];
    private bool disposed;

    public Aes256Cipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException("AES-256 requires a 32-byte key", nameof(key));

        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        byte[] keyCopy = key.ToArray();
        try
        {
            aes.Key = keyCopy;
            encryptor = aes.CreateEncryptor();
            try
            {
                decryptor = aes.CreateDecryptor();
            }
            catch
            {
                encryptor.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyCopy);
        }
    }

    public void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output) => Transform(encryptor, input, output);

    public void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output) => Transform(decryptor, input, output);

    private void Transform(ICryptoTransform transform, ReadOnlySpan<byte> input, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (input.Length != BlockSize || output.Length != BlockSize)
            throw new ArgumentException("AES-256 input and output must each hold one 16-byte block");

        input.CopyTo(inputBlock);
        try
        {
            if (transform.TransformBlock(inputBlock, 0, BlockSize, outputBlock, 0) != BlockSize)
                throw new CryptographicException("The AES provider returned an incomplete block");
            outputBlock.AsSpan().CopyTo(output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inputBlock);
            CryptographicOperations.ZeroMemory(outputBlock);
        }
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        try
        {
            encryptor.Dispose();
        }
        finally
        {
            decryptor.Dispose();
        }
    }
}

using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Abc.Cryptography;

/// <summary>Detached AES-256-GCM backed by the .NET authenticated-encryption provider.</summary>
public sealed class Aes256GcmCipher : IDisposable
{
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    private const int StackLimit = 1024;

    private readonly AesGcm cipher;

    public static bool IsSupported => AesGcm.IsSupported;

    public Aes256GcmCipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException("AES-256-GCM requires a 32-byte key", nameof(key));
        cipher = new AesGcm(key, TagSize);
    }

    /// <summary>Seal using a nonce that is unique for this key.</summary>
    public void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData,
                     ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {
        Validate(nonce, tag, plaintext.Length, ciphertext.Length);
        if (ciphertext.Overlaps(tag))
            throw new ArgumentException("Ciphertext and tag outputs must be disjoint");

        byte[]? rented = null;
        Span<byte> staged = plaintext.Length <= StackLimit ? stackalloc byte[plaintext.Length]
            : (rented = ArrayPool<byte>.Shared.Rent(plaintext.Length)).AsSpan(0, plaintext.Length);
        Span<byte> stagedTag = stackalloc byte[TagSize];
        try
        {
            cipher.Encrypt(nonce, plaintext, staged, stagedTag, associatedData);
            staged.CopyTo(ciphertext);
            stagedTag.CopyTo(tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(staged);
            CryptographicOperations.ZeroMemory(stagedTag);
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>Return false for a bad tag and preserve the caller's plaintext buffer.</summary>
    public bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData,
                     ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        Validate(nonce, tag, ciphertext.Length, plaintext.Length);
        byte[]? rented = null;
        Span<byte> staged = ciphertext.Length <= StackLimit ? stackalloc byte[ciphertext.Length]
            : (rented = ArrayPool<byte>.Shared.Rent(ciphertext.Length)).AsSpan(0, ciphertext.Length);
        try
        {
            cipher.Decrypt(nonce, ciphertext, tag, staged, associatedData);
            staged.CopyTo(plaintext);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(staged);
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public void Dispose() => cipher.Dispose();

    private static void Validate(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, int inputSize, int outputSize)
    {
        if (nonce.Length != NonceSize)
            throw new ArgumentException("AES-256-GCM requires a 12-byte nonce", nameof(nonce));
        if (tag.Length != TagSize)
            throw new ArgumentException("AES-256-GCM requires a 16-byte tag", nameof(tag));
        if (inputSize != outputSize)
            throw new ArgumentException("AES-256-GCM input and output lengths must match");
    }
}

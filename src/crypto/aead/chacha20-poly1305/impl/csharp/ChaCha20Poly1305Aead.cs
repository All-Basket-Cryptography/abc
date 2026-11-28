using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Abc.Cryptography;

public static class ChaCha20Poly1305Aead
{
    public const int KeySize = ChaCha20Cipher.KeySize;
    public const int NonceSize = ChaCha20Cipher.NonceSize;
    public const int TagSize = Poly1305Mac.TagSize;

    public static void Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {
        Validate(key, nonce, plaintext.Length, ciphertext.Length);
        if (tag.Length != TagSize) throw new ArgumentException("Expected a 16-byte tag.", nameof(tag));
        ciphertext = ciphertext[..plaintext.Length];
        if (ciphertext.Overlaps(tag))
            throw new ArgumentException("Ciphertext and tag destinations overlap.", nameof(tag));

        using var mac = BeginMac(key, nonce);
        UpdatePadded(mac, aad);
        ChaCha20Cipher.Xor(key, nonce, 1, plaintext, ciphertext);
        CompleteMac(mac, aad.Length, ciphertext, tag);
    }

    public static bool TryOpen(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                               ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        Validate(key, nonce, ciphertext.Length, plaintext.Length);
        if (tag.Length != TagSize) return false;

        // Authenticate and decrypt the same bytes even if the caller reuses mutable storage.
        byte[] verifiedInput = ciphertext.ToArray();
        Span<byte> parameters = stackalloc byte[KeySize + NonceSize];
        key.CopyTo(parameters[..KeySize]);
        nonce.CopyTo(parameters[KeySize..]);
        Span<byte> calculated = stackalloc byte[TagSize];
        try
        {
            using var mac = BeginMac(parameters[..KeySize], parameters[KeySize..]);
            UpdatePadded(mac, aad);
            CompleteMac(mac, aad.Length, verifiedInput, calculated);
            if (!CryptographicOperations.FixedTimeEquals(calculated, tag)) return false;

            ChaCha20Cipher.Xor(parameters[..KeySize], parameters[KeySize..], 1, verifiedInput, plaintext);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(parameters);
            CryptographicOperations.ZeroMemory(calculated);
        }
    }

    private static void Validate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int count, int destination)
    {
        if (key.Length != KeySize) throw new ArgumentException("Expected a 32-byte key.", nameof(key));
        if (nonce.Length != NonceSize) throw new ArgumentException("Expected a 12-byte nonce.", nameof(nonce));
        if (!ChaCha20Cipher.FitsCounter((ulong)count, 1))
            throw new ArgumentOutOfRangeException(nameof(count), "ChaCha20-Poly1305 counter would wrap.");
        if (destination < count) throw new ArgumentException("Payload destination is too short.", nameof(destination));
    }

    private static Poly1305Mac BeginMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        Span<byte> block = stackalloc byte[ChaCha20Cipher.BlockSize];
        try
        {
            ChaCha20Cipher.Block(key, nonce, 0, block);
            return new Poly1305Mac(block[..Poly1305Mac.KeySize]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }
    }

    private static void UpdatePadded(Poly1305Mac mac, ReadOnlySpan<byte> input)
    {
        mac.Update(input);
        Span<byte> zeros = stackalloc byte[TagSize];
        zeros.Clear();
        mac.Update(zeros[..((TagSize - input.Length % TagSize) % TagSize)]);
    }

    private static void CompleteMac(Poly1305Mac mac, int aadLength, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
    {
        UpdatePadded(mac, ciphertext);
        Span<byte> lengths = stackalloc byte[TagSize];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)aadLength);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertext.Length);
        mac.Update(lengths);
        mac.Finish(tag);
    }
}

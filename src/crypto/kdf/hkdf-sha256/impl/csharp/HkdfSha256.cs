using System;

namespace Abc.Cryptography;

public enum HkdfStatus
{
    Success,
    PrkTooShort,
    OutputTooLong,
    InfoOverlapsOutput,
}

/// <summary>RFC 5869 extract and expand using the portable managed HMAC-SHA-256.</summary>
public static class HkdfSha256
{
    public const int PrkSize = HmacSha256.TagSize;
    public const int MaxOutputBytes = 255 * PrkSize;

    public static Sha256Status Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ikm,
                                       Span<byte> destination)
    {
        // An empty HMAC key has the same padded key as a zero-filled salt.
        return HmacSha256.Authenticate(salt, ikm, destination);
    }

    public static HkdfStatus Expand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, Span<byte> output)
    {
        if (prk.Length < PrkSize)
            return HkdfStatus.PrkTooShort;
        HkdfStatus status = ValidateExpansion(info, output);
        if (status != HkdfStatus.Success)
            return status;

        Span<byte> key = stackalloc byte[PrkSize];
        if (prk.Length > Sha256Hasher.BlockSize)
        {
            _ = Sha256Hasher.Hash(prk, key);
            return ExpandBlocks(key, info, output);
        }
        // Copy once before output writes, including when PRK overlaps output.
        Span<byte> original = stackalloc byte[Sha256Hasher.BlockSize];
        prk.CopyTo(original);
        return ExpandBlocks(original[..prk.Length], info, output);
    }

    public static HkdfStatus Derive(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ikm,
                                    ReadOnlySpan<byte> info, Span<byte> output)
    {
        HkdfStatus status = ValidateExpansion(info, output);
        if (status != HkdfStatus.Success)
            return status;
        Span<byte> prk = stackalloc byte[PrkSize];
        _ = Extract(salt, ikm, prk);
        return ExpandBlocks(prk, info, output);
    }

    private static HkdfStatus ValidateExpansion(ReadOnlySpan<byte> info, Span<byte> output)
    {
        if (output.Length > MaxOutputBytes)
            return HkdfStatus.OutputTooLong;
        return info.Overlaps(output) ? HkdfStatus.InfoOverlapsOutput : HkdfStatus.Success;
    }

    private static HkdfStatus ExpandBlocks(ReadOnlySpan<byte> key, ReadOnlySpan<byte> info, Span<byte> output)
    {
        Span<byte> previous = stackalloc byte[PrkSize];
        Span<byte> counter = stackalloc byte[1];
        for (int offset = 0; offset < output.Length; offset += PrkSize)
        {
            var hmac = new HmacSha256(key);
            if (offset != 0)
                _ = hmac.Update(previous);
            _ = hmac.Update(info);
            counter[0] = (byte)(offset / PrkSize + 1);
            _ = hmac.Update(counter);
            _ = hmac.Digest(previous);
            previous[..Math.Min(PrkSize, output.Length - offset)].CopyTo(output[offset..]);
        }
        return HkdfStatus.Success;
    }
}

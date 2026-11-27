package org.allbasket.abc.kdf.hkdfsha256;

import java.util.Objects;
import org.allbasket.abc.hash.sha256.Sha256;
import org.allbasket.abc.mac.hmacsha256.HmacSha256;

/** RFC 5869 extract and expand using the portable Java HMAC-SHA-256. */
public final class HkdfSha256 {
    public static final int PRK_BYTES = HmacSha256.TAG_BYTES;
    public static final int MAX_OUTPUT_BYTES = 255 * PRK_BYTES;

    private HkdfSha256() {}

    /** A null salt uses the RFC default of HashLen zero bytes. */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        return HmacSha256.authenticate(salt == null ? new byte[PRK_BYTES] : salt, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int outputLength) {
        if (prk.length < PRK_BYTES) {
            throw new IllegalArgumentException("HKDF PRK must be at least 32 bytes");
        }
        validateExpansion(info, outputLength);
        byte[] key = prk.length > 64 ? Sha256.hash(prk) : prk;
        return expandBlocks(key, info, outputLength);
    }

    public static byte[] derive(byte[] salt, byte[] ikm, byte[] info, int outputLength) {
        validateExpansion(info, outputLength);
        return expandBlocks(extract(salt, ikm), info, outputLength);
    }

    private static void validateExpansion(byte[] info, int outputLength) {
        if (outputLength < 0 || outputLength > MAX_OUTPUT_BYTES) {
            throw new IllegalArgumentException("HKDF output must be between 0 and 8160 bytes");
        }
        Objects.requireNonNull(info, "info");
    }

    private static byte[] expandBlocks(byte[] key, byte[] info, int outputLength) {
        byte[] output = new byte[outputLength];
        byte[] previous = new byte[0];
        byte[] counter = new byte[1];
        for (int offset = 0; offset < outputLength; offset += PRK_BYTES) {
            counter[0] = (byte) (offset / PRK_BYTES + 1);
            previous = new HmacSha256(key).update(previous).update(info).update(counter).digest();
            System.arraycopy(previous, 0, output, offset, Math.min(PRK_BYTES, outputLength - offset));
        }
        return output;
    }
}

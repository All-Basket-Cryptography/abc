package org.allbasket.abc.kdf.pbkdf2sha256;

import java.util.Objects;
import org.allbasket.abc.hash.sha256.Sha256;
import org.allbasket.abc.mac.hmacsha256.HmacSha256;

/** RFC 8018 PBKDF2 over byte strings using the portable Java HMAC-SHA-256 core. */
public final class Pbkdf2Sha256 {
    public static final long MAX_ITERATIONS = 0xffff_ffffL;
    private static final int TAG_BYTES = HmacSha256.TAG_BYTES;

    private Pbkdf2Sha256() {}

    public static byte[] derive(byte[] password, byte[] salt, long iterations, int outputLength) {
        if (iterations < 1 || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("PBKDF2 iterations must be between 1 and 2^32 - 1");
        }
        if (outputLength < 1) {
            throw new IllegalArgumentException("PBKDF2 requires a positive output length");
        }
        Objects.requireNonNull(salt, "salt");
        byte[] key = password.length > 64 ? Sha256.hash(password) : password;
        byte[] output = new byte[outputLength];
        for (int offset = 0; offset < outputLength;) {
            byte[] bytes = block(key, salt, iterations, offset / TAG_BYTES + 1);
            int count = Math.min(bytes.length, outputLength - offset);
            System.arraycopy(bytes, 0, output, offset, count);
            offset += count;
        }
        return output;
    }

    private static byte[] block(byte[] key, byte[] salt, long iterations, int index) {
        byte[] counter = {
            (byte) (index >>> 24), (byte) (index >>> 16), (byte) (index >>> 8), (byte) index,
        };
        byte[] previous = new HmacSha256(key).update(salt).update(counter).digest();
        byte[] accumulated = previous.clone();
        for (long round = 1; round < iterations; round++) {
            previous = HmacSha256.authenticate(key, previous);
            for (int i = 0; i < accumulated.length; i++) {
                accumulated[i] ^= previous[i];
            }
        }
        return accumulated;
    }
}

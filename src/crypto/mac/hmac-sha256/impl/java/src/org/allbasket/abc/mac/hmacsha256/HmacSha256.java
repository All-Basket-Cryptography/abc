package org.allbasket.abc.mac.hmacsha256;

import java.util.Arrays;
import org.allbasket.abc.hash.sha256.Sha256;

/** Streaming full-tag HMAC-SHA-256 over the portable Java SHA-256 core. */
public final class HmacSha256 {
    public static final int TAG_BYTES = Sha256.DIGEST_BYTES;
    public static final long MAX_MESSAGE_BYTES = Sha256.MAX_MESSAGE_BYTES - 64;

    private static final int BLOCK_BYTES = 64;
    private final Sha256 inner = new Sha256();
    private final byte[] outerPad = new byte[BLOCK_BYTES];

    public HmacSha256(byte[] key) {
        byte[] normalized = key.length > BLOCK_BYTES ? Sha256.hash(key) : key;
        byte[] pad = Arrays.copyOf(normalized, BLOCK_BYTES);
        for (int i = 0; i < pad.length; i++) {
            outerPad[i] = (byte) (pad[i] ^ 0x5c);
            pad[i] ^= 0x36;
        }
        inner.update(pad);
    }

    public HmacSha256 update(byte[] input) {
        return update(input, 0, input.length);
    }

    /** Append a slice. An invalid range or excessive total preserves the state. */
    public HmacSha256 update(byte[] input, int offset, int length) {
        inner.update(input, offset, length);
        return this;
    }

    /** Return a fresh snapshot of the full tag, with the context still open. */
    public byte[] digest() {
        return new Sha256().update(outerPad).update(inner.digest()).digest();
    }

    public static byte[] authenticate(byte[] key, byte[] input) {
        return new HmacSha256(key).update(input).digest();
    }
}

package org.allbasket.abc.aead.chacha20poly1305;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

import org.allbasket.abc.cipher.chacha20.ChaCha20;
import org.allbasket.abc.mac.poly1305.Poly1305;

/** RFC 8439 authenticated encryption with detached tags and 96-bit nonces. */
public final class ChaCha20Poly1305 {
    public static final int KEY_BYTES = ChaCha20.KEY_BYTES;
    public static final int NONCE_BYTES = ChaCha20.NONCE_BYTES;
    public static final int TAG_BYTES = Poly1305.TAG_BYTES;
    public static final long MAX_PAYLOAD_BYTES = ((1L << 32) - 1) * ChaCha20.BLOCK_BYTES;
    private static final byte[] ZEROES = new byte[16];
    private static final VarHandle LENGTH =
        MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

    private ChaCha20Poly1305() {}

    /** The returned arrays belong to the caller. */
    public record Sealed(byte[] ciphertext, byte[] tag) {}

    /** Encrypt and authenticate using a nonce that is unique under this key. */
    public static Sealed seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        validate(key, nonce, plaintext.length);
        byte[] fixedKey = key.clone();
        try {
            byte[] fixedNonce = nonce.clone();
            byte[] ciphertext = plaintext.clone();
            xorPayload(fixedKey, fixedNonce, ciphertext);
            return new Sealed(ciphertext, authenticate(fixedKey, fixedNonce, aad, ciphertext));
        } finally {
            Arrays.fill(fixedKey, (byte) 0);
        }
    }

    /** Return owned plaintext on authentication success, or null on authentication failure. */
    public static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag) {
        validate(key, nonce, ciphertext.length);
        if (tag.length != TAG_BYTES) {
            return null;
        }
        byte[] fixedKey = key.clone();
        try {
            byte[] fixedNonce = nonce.clone();
            byte[] work = ciphertext.clone();
            byte[] expected = authenticate(fixedKey, fixedNonce, aad, work);
            if (!MessageDigest.isEqual(expected, tag)) {
                return null;
            }
            xorPayload(fixedKey, fixedNonce, work);
            return work;
        } finally {
            Arrays.fill(fixedKey, (byte) 0);
        }
    }

    private static void validate(byte[] key, byte[] nonce, int payloadBytes) {
        if (key.length != KEY_BYTES || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("ChaCha20-Poly1305 requires a 32-byte key and 12-byte nonce");
        }
        if (payloadBytes > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("ChaCha20-Poly1305 payload exceeds the counter range");
        }
    }

    private static void xorPayload(byte[] key, byte[] nonce, byte[] payload) {
        try (ChaCha20 stream = new ChaCha20(key, nonce, 1)) {
            stream.apply(payload);
        }
    }

    private static Poly1305 newMac(byte[] key, byte[] nonce) {
        byte[] stream = ChaCha20.block(key, nonce, 0);
        try {
            byte[] oneTimeKey = Arrays.copyOf(stream, Poly1305.KEY_BYTES);
            try {
                return new Poly1305(oneTimeKey);
            } finally {
                Arrays.fill(oneTimeKey, (byte) 0);
            }
        } finally {
            Arrays.fill(stream, (byte) 0);
        }
    }

    private static byte[] authenticate(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) {
        try (Poly1305 mac = newMac(key, nonce)) {
            updatePadded(mac, aad);
            updatePadded(mac, ciphertext);
            byte[] lengths = new byte[16];
            LENGTH.set(lengths, 0, (long) aad.length);
            LENGTH.set(lengths, 8, (long) ciphertext.length);
            mac.update(lengths);
            return mac.finish();
        }
    }

    private static void updatePadded(Poly1305 mac, byte[] input) {
        mac.update(input);
        mac.update(ZEROES, 0, (16 - input.length % 16) % 16);
    }
}

package org.allbasket.abc.aead.aes256gcm;

import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-GCM with fixed 96-bit nonces and detached 128-bit tags. */
public final class Aes256Gcm {
    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 16;
    public static final long MAX_PAYLOAD_BYTES = ((1L << 32) - 2) * 16;
    public static final int MAX_ARRAY_PAYLOAD_BYTES = Integer.MAX_VALUE - TAG_BYTES;
    private final SecretKeySpec key;
    private final Provider provider;

    public Aes256Gcm(byte[] key) throws NoSuchProviderException {
        if (key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-256-GCM requires a 32-byte key");
        }
        provider = Security.getProvider("SunJCE");
        if (provider == null || provider.getClass().getModule() != Object.class.getModule()
                || !provider.getClass().getName().equals("com.sun.crypto.provider.SunJCE")) {
            throw new NoSuchProviderException("The built-in SunJCE provider is required");
        }
        this.key = new SecretKeySpec(key, "AES");
    }

    /** The returned arrays belong to the caller. */
    public record Sealed(byte[] ciphertext, byte[] tag) {}

    /** Encrypt with a nonce that is unique under this key. */
    public Sealed seal(byte[] nonce, byte[] aad, byte[] plaintext) throws GeneralSecurityException {
        validate(nonce, plaintext.length);
        Cipher cipher = initialize(Cipher.ENCRYPT_MODE, nonce, aad);
        byte[] combined = cipher.doFinal(plaintext);
        int length = plaintext.length;
        return new Sealed(Arrays.copyOf(combined, length), Arrays.copyOfRange(combined, length, combined.length));
    }

    /** Return owned plaintext on authentication success, or null on authentication failure. */
    public byte[] open(byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag) throws GeneralSecurityException {
        validate(nonce, ciphertext.length);
        if (tag.length != TAG_BYTES) {
            return null;
        }
        byte[] combined = Arrays.copyOf(ciphertext, ciphertext.length + TAG_BYTES);
        System.arraycopy(tag, 0, combined, ciphertext.length, TAG_BYTES);
        Cipher cipher = initialize(Cipher.DECRYPT_MODE, nonce, aad);
        try {
            return cipher.doFinal(combined);
        } catch (AEADBadTagException error) {
            return null;
        }
    }

    private static void validate(byte[] nonce, int bytes) {
        if (nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("AES-256-GCM requires a 12-byte nonce");
        }
        if (bytes > MAX_ARRAY_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("AES-256-GCM payload and tag exceed the byte-array representation");
        }
    }

    private Cipher initialize(int mode, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
        cipher.init(mode, key, new GCMParameterSpec(8 * TAG_BYTES, nonce));
        cipher.updateAAD(aad);
        return cipher;
    }
}

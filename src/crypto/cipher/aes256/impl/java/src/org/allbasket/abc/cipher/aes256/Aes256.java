package org.allbasket.abc.cipher.aes256;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Single-block AES-256 with the JVM's built-in SunJCE provider. */
public final class Aes256 {
    public static final int KEY_BYTES = 32;
    public static final int BLOCK_BYTES = 16;
    private static final String TRANSFORMATION = "AES/ECB/NoPadding";
    private final Cipher encrypt;
    private final Cipher decrypt;

    public Aes256(byte[] key) throws GeneralSecurityException {
        if (key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-256 requires a 32-byte key");
        }
        Provider provider = Security.getProvider("SunJCE");
        if (provider == null || provider.getClass().getModule() != Object.class.getModule()
                || !provider.getClass().getName().equals("com.sun.crypto.provider.SunJCE")) {
            throw new java.security.NoSuchProviderException("The built-in SunJCE provider is required");
        }
        SecretKeySpec ownedKey = new SecretKeySpec(key, "AES");
        encrypt = Cipher.getInstance(TRANSFORMATION, provider);
        decrypt = Cipher.getInstance(TRANSFORMATION, provider);
        encrypt.init(Cipher.ENCRYPT_MODE, ownedKey);
        decrypt.init(Cipher.DECRYPT_MODE, ownedKey);
    }

    public byte[] encryptBlock(byte[] block) throws GeneralSecurityException {
        return apply(encrypt, block);
    }

    public byte[] decryptBlock(byte[] block) throws GeneralSecurityException {
        return apply(decrypt, block);
    }

    private static byte[] apply(Cipher cipher, byte[] block) throws GeneralSecurityException {
        if (block.length != BLOCK_BYTES) {
            throw new IllegalArgumentException("AES-256 accepts exactly one 16-byte block");
        }
        return cipher.doFinal(block);
    }
}

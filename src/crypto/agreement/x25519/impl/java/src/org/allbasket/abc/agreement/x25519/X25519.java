package org.allbasket.abc.agreement.x25519;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import javax.crypto.KeyAgreement;

/** RFC 7748 raw X25519 with the built-in SunEC provider. */
public final class X25519 {
    public static final int KEY_BYTES = 32;
    private static final String ALGORITHM = "X25519";
    private static final BigInteger FIELD = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    private X25519() {}

    public static byte[] publicKey(byte[] privateKey) throws GeneralSecurityException {
        requireWidth(privateKey);
        byte[] result = agreement(privateKey, BigInteger.valueOf(9));
        if (result == null) {
            throw new InvalidKeyException("SunEC rejected the X25519 base point");
        }
        return result;
    }

    /** Return the 32-byte shared secret, or null for an invalid low-order peer. */
    public static byte[] sharedSecret(byte[] privateKey, byte[] peer) throws GeneralSecurityException {
        requireWidth(privateKey);
        requireWidth(peer);
        byte[] coordinate = new byte[KEY_BYTES];
        for (int i = 0; i < KEY_BYTES; i++) {
            coordinate[i] = peer[KEY_BYTES - 1 - i];
        }
        coordinate[0] &= 0x7f;
        return agreement(privateKey, new BigInteger(1, coordinate).mod(FIELD));
    }

    private static void requireWidth(byte[] key) {
        if (key.length != KEY_BYTES) {
            throw new IllegalArgumentException("X25519 requires 32-byte keys");
        }
    }

    private static Provider builtInProvider() throws NoSuchProviderException {
        Provider provider = Security.getProvider("SunEC");
        Module origin = ModuleLayer.boot().findModule("jdk.crypto.ec").orElse(null);
        if (provider == null || provider.getClass().getModule() != origin ||
                !provider.getClass().getName().equals("sun.security.ec.SunEC")) {
            throw new NoSuchProviderException("The built-in SunEC provider is required");
        }
        return provider;
    }

    private static byte[] agreement(byte[] privateKey, BigInteger u) throws GeneralSecurityException {
        Provider provider = builtInProvider();
        KeyFactory factory = KeyFactory.getInstance(ALGORITHM, provider);
        KeyAgreement x25519 = KeyAgreement.getInstance(ALGORITHM, provider);
        x25519.init(factory.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, privateKey)));
        var peerKey = factory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
        try {
            x25519.doPhase(peerKey, true);
        } catch (InvalidKeyException lowOrder) {
            return null;
        }
        byte[] secret = x25519.generateSecret();
        if (secret.length != KEY_BYTES) {
            throw new GeneralSecurityException("SunEC returned an unexpected X25519 output length");
        }
        int nonzero = 0;
        for (byte value : secret) {
            nonzero |= value;
        }
        return nonzero == 0 ? null : secret;
    }
}

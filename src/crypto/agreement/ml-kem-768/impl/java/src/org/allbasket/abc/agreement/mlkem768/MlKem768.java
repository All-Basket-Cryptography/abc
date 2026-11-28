package org.allbasket.abc.agreement.mlkem768;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

/** Seed-format FIPS 203 ML-KEM-768 via the pinned Bouncy Castle lightweight API. */
public final class MlKem768 {
    public static final int SEED_BYTES = 64;
    public static final int PUBLIC_BYTES = 1184;
    public static final int CIPHERTEXT_BYTES = 1088;
    public static final int SECRET_BYTES = 32;
    private static final int POLYNOMIAL_BYTES = 1152;
    private static final int MODULUS = 3329;
    private static final MLKEMParameters PARAMETERS = MLKEMParameters.ml_kem_768;
    private static final SecureRandom RANDOM = new SecureRandom();

    private MlKem768() {}

    /** Returned ciphertext and secret arrays belong to the caller. */
    public record Encapsulation(byte[] ciphertext, byte[] secret) {}

    public static DecapsulationKey generateKey() {
        byte[] seed = new byte[SEED_BYTES];
        try {
            RANDOM.nextBytes(seed);
            return fromSeed(seed);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    public static DecapsulationKey fromSeed(byte[] seed) {
        if (seed.length != SEED_BYTES) {
            throw new IllegalArgumentException("ML-KEM-768 requires a 64-byte d || z seed");
        }
        return new DecapsulationKey(new MLKEMPrivateKeyParameters(PARAMETERS, seed));
    }

    public static Encapsulation encapsulate(byte[] publicKey) {
        if (publicKey.length != PUBLIC_BYTES) {
            throw new IllegalArgumentException("Incorrect ML-KEM-768 public key length");
        }
        byte[] encoded = publicKey.clone();
        for (int i = 0; i < POLYNOMIAL_BYTES; i += 3) {
            int a = Byte.toUnsignedInt(encoded[i]);
            int b = Byte.toUnsignedInt(encoded[i + 1]);
            int c = Byte.toUnsignedInt(encoded[i + 2]);
            if ((a | ((b & 15) << 8)) >= MODULUS || ((b >>> 4) | (c << 4)) >= MODULUS) {
                throw new IllegalArgumentException("Noncanonical ML-KEM-768 public key");
            }
        }
        var key = new MLKEMPublicKeyParameters(PARAMETERS, encoded);
        SecretWithEncapsulation encapsulated = new MLKEMGenerator(RANDOM).generateEncapsulated(key);
        try {
            return new Encapsulation(encapsulated.getEncapsulation(), encapsulated.getSecret());
        } finally {
            try {
                encapsulated.destroy();
            } catch (DestroyFailedException failure) {
                throw new IllegalStateException("Could not clear the provider encapsulation", failure);
            }
        }
    }

    public static final class DecapsulationKey implements AutoCloseable {
        private MLKEMPrivateKeyParameters key;

        private DecapsulationKey(MLKEMPrivateKeyParameters key) {
            this.key = key;
        }

        public synchronized byte[] publicKey() {
            return requireKey().getPublicKey();
        }

        /** Returns the implicit-rejection secret for a correctly sized invalid ciphertext. */
        public synchronized byte[] decapsulate(byte[] ciphertext) {
            MLKEMPrivateKeyParameters current = requireKey();
            if (ciphertext.length != CIPHERTEXT_BYTES) {
                throw new IllegalArgumentException("Incorrect ML-KEM-768 ciphertext length");
            }
            return new MLKEMExtractor(current).extractSecret(ciphertext);
        }

        @Override
        public synchronized void close() {
            if (key != null) {
                key.destroy();
                key = null;
            }
        }

        private MLKEMPrivateKeyParameters requireKey() {
            if (key == null) {
                throw new IllegalStateException("ML-KEM-768 key is closed");
            }
            return key;
        }
    }
}

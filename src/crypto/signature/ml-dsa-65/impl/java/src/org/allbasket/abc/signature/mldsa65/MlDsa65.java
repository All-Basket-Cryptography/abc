package org.allbasket.abc.signature.mldsa65;

import java.util.Arrays;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.signers.MLDSASigner;

/** Pure deterministic FIPS 204 ML-DSA-65 with binary context and raw encodings. */
public final class MlDsa65 {
    public static final int SEED_BYTES = 32;
    public static final int PUBLIC_BYTES = 1952;
    public static final int SIGNATURE_BYTES = 3309;
    public static final int MAX_CONTEXT_BYTES = 255;
    private static final int MAX_HINTS = 55;
    private static final int HINT_POLYNOMIALS = 6;
    private static final int HINT_OFFSET = SIGNATURE_BYTES - MAX_HINTS - HINT_POLYNOMIALS;
    private static final MLDSAParameters PARAMETERS = MLDSAParameters.ml_dsa_65;

    private MlDsa65() {}

    public static byte[] publicKey(byte[] seed) {
        var key = importSeed(seed);
        try {
            return key.getPublicKey();
        } finally {
            key.destroy();
        }
    }

    public static byte[] sign(byte[] seed, byte[] message, byte[] context) throws CryptoException {
        if (context.length > MAX_CONTEXT_BYTES) {
            throw new IllegalArgumentException("ML-DSA-65 context exceeds 255 bytes");
        }
        var key = importSeed(seed);
        try {
            var signer = new MLDSASigner();
            signer.init(true, new ParametersWithContext(key, context));
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        } finally {
            key.destroy();
        }
    }

    public static boolean verify(byte[] publicKey, byte[] message, byte[] context, byte[] signature) {
        if (publicKey.length != PUBLIC_BYTES || context.length > MAX_CONTEXT_BYTES ||
                signature.length != SIGNATURE_BYTES) {
            return false;
        }
        byte[] encoded = signature.clone();
        if (!canonicalHints(encoded)) {
            return false;
        }
        var key = new MLDSAPublicKeyParameters(PARAMETERS, publicKey);
        var verifier = new MLDSASigner();
        verifier.init(false, new ParametersWithContext(key, context));
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(encoded);
    }

    private static MLDSAPrivateKeyParameters importSeed(byte[] seed) {
        if (seed.length != SEED_BYTES) {
            throw new IllegalArgumentException("ML-DSA-65 requires a 32-byte seed");
        }
        // The pinned provider retains the supplied seed array and clears it on destroy.
        byte[] owned = seed.clone();
        try {
            return new MLDSAPrivateKeyParameters(PARAMETERS, owned);
        } catch (RuntimeException | Error failure) {
            Arrays.fill(owned, (byte) 0);
            throw failure;
        }
    }

    private static boolean canonicalHints(byte[] signature) {
        int start = 0;
        for (int i = 0; i < HINT_POLYNOMIALS; i++) {
            int end = Byte.toUnsignedInt(signature[HINT_OFFSET + MAX_HINTS + i]);
            if (end < start || end > MAX_HINTS) {
                return false;
            }
            int previous = -1;
            for (int j = start; j < end; j++) {
                int index = Byte.toUnsignedInt(signature[HINT_OFFSET + j]);
                if (index <= previous) {
                    return false;
                }
                previous = index;
            }
            start = end;
        }
        for (int j = start; j < MAX_HINTS; j++) {
            if (signature[HINT_OFFSET + j] != 0) {
                return false;
            }
        }
        return true;
    }
}

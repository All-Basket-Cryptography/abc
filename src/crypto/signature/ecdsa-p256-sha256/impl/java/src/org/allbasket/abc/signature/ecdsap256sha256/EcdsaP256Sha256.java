package org.allbasket.abc.signature.ecdsap256sha256;

import java.math.BigInteger;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;

/** RFC 6979 deterministic P-256 ECDSA with SHA-256 and P1363 signatures. */
public final class EcdsaP256Sha256 {
    public static final int PRIVATE_KEY_BYTES = 32;
    public static final int PUBLIC_KEY_BYTES = 65;
    public static final int COMPRESSED_KEY_BYTES = 33;
    public static final int SIGNATURE_BYTES = 64;
    private static final ECDomainParameters DOMAIN = domain();

    private EcdsaP256Sha256() {}

    public static byte[] publicKey(byte[] scalar) {
        BigInteger d = privateScalar(scalar);
        return new FixedPointCombMultiplier().multiply(DOMAIN.getG(), d).getEncoded(false);
    }

    public static byte[] sign(byte[] scalar, byte[] message) {
        var key = new ECPrivateKeyParameters(privateScalar(scalar), DOMAIN);
        var signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, key);
        BigInteger[] signature = signer.generateSignature(hash(message));
        byte[] result = new byte[SIGNATURE_BYTES];
        for (int i = 0; i < signature.length; i++) {
            byte[] word = BigIntegers.asUnsignedByteArray(PRIVATE_KEY_BYTES, signature[i]);
            System.arraycopy(word, 0, result, i * PRIVATE_KEY_BYTES, PRIVATE_KEY_BYTES);
        }
        return result;
    }

    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        boolean compressed = publicKey.length == COMPRESSED_KEY_BYTES &&
            (publicKey[0] == 2 || publicKey[0] == 3);
        boolean uncompressed = publicKey.length == PUBLIC_KEY_BYTES && publicKey[0] == 4;
        if ((!compressed && !uncompressed) || signature.length != SIGNATURE_BYTES) {
            return false;
        }
        var r = new BigInteger(1, signature, 0, PRIVATE_KEY_BYTES);
        var s = new BigInteger(1, signature, PRIVATE_KEY_BYTES, PRIVATE_KEY_BYTES);
        if (!validScalar(r) || !validScalar(s)) {
            return false;
        }
        ECPublicKeyParameters key;
        try {
            var point = DOMAIN.getCurve().decodePoint(publicKey);
            if (!java.util.Arrays.equals(publicKey, point.getEncoded(compressed))) {
                return false;
            }
            key = new ECPublicKeyParameters(point, DOMAIN);
        } catch (IllegalArgumentException invalidPoint) {
            return false;
        }
        var verifier = new ECDSASigner();
        verifier.init(false, key);
        return verifier.verifySignature(hash(message), r, s);
    }

    private static BigInteger privateScalar(byte[] scalar) {
        if (scalar.length != PRIVATE_KEY_BYTES) {
            throw new IllegalArgumentException("P-256 private scalar must be 32 bytes");
        }
        var value = new BigInteger(1, scalar);
        if (!validScalar(value)) {
            throw new IllegalArgumentException("P-256 private scalar is outside 1..n-1");
        }
        return value;
    }

    private static boolean validScalar(BigInteger value) {
        return value.signum() > 0 && value.compareTo(DOMAIN.getN()) < 0;
    }

    private static byte[] hash(byte[] message) {
        var digest = new SHA256Digest();
        digest.update(message, 0, message.length);
        byte[] result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }

    private static ECDomainParameters domain() {
        var p = CustomNamedCurves.getByName("secp256r1");
        return new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
    }
}

package org.allbasket.abc.signature.ecdsap256sha256;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
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
        BigInteger[] signature;
        try (var nonce = new Nonce()) {
            var signer = new ECDSASigner(nonce);
            signer.init(true, key);
            signature = signer.generateSignature(hash(message));
        }
        byte[] result = new byte[SIGNATURE_BYTES];
        for (int i = 0; i < signature.length; i++) {
            byte[] word = BigIntegers.asUnsignedByteArray(PRIVATE_KEY_BYTES, signature[i]);
            System.arraycopy(word, 0, result, i * PRIVATE_KEY_BYTES, PRIVATE_KEY_BYTES);
        }
        return result;
    }

    private static final class Nonce implements DSAKCalculator, AutoCloseable {
        private final HMac mac = new HMac(new SHA256Digest());
        private final byte[] key = new byte[PRIVATE_KEY_BYTES];
        private final byte[] value = new byte[PRIVATE_KEY_BYTES];
        private BigInteger order;
        private boolean issued;

        public boolean isDeterministic() { return true; }

        public void init(BigInteger n, SecureRandom random) {
            throw new UnsupportedOperationException("Only deterministic signing is supported");
        }

        public void init(BigInteger n, BigInteger scalar, byte[] digest) {
            order = n;
            issued = false;
            Arrays.fill(key, (byte) 0);
            Arrays.fill(value, (byte) 1);
            byte[] secret = BigIntegers.asUnsignedByteArray(PRIVATE_KEY_BYTES, scalar);
            byte[] hashed = BigIntegers.asUnsignedByteArray(PRIVATE_KEY_BYTES, new BigInteger(1, digest).mod(n));
            try {
                mac.init(new KeyParameter(key));
                updateKey((byte) 0, secret, hashed);
                updateKey((byte) 1, secret, hashed);
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
        }

        private void updateKey(byte separator, byte[]... suffix) {
            mac.update(value, 0, value.length);
            mac.update(separator);
            for (byte[] part : suffix) mac.update(part, 0, part.length);
            mac.doFinal(key, 0);
            mac.init(new KeyParameter(key));
            advanceValue();
        }

        private void advanceValue() {
            mac.update(value, 0, value.length);
            mac.doFinal(value, 0);
        }

        public BigInteger nextK() {
            // The signer requests another k after a zero r or s. RFC 6979 §3.2(h.3)
            // requires the same state update as a candidate outside 1..n−1.
            if (issued) updateKey((byte) 0);
            while (true) {
                advanceValue();
                BigInteger candidate = new BigInteger(1, value);
                if (candidate.signum() > 0 && candidate.compareTo(order) < 0) {
                    issued = true;
                    return candidate;
                }
                updateKey((byte) 0);
            }
        }

        public void close() {
            Arrays.fill(value, (byte) 0);
            Arrays.fill(key, (byte) 0);
            mac.init(new KeyParameter(key));
        }
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

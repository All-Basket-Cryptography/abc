package org.allbasket.abc.signature.ed25519;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/** Pure Ed25519 with seed-only signing and strict point validation. */
public final class Ed25519 {
    public static final int SEED_BYTES = 32;
    public static final int PUBLIC_BYTES = 32;
    public static final int SIGNATURE_BYTES = 64;
    private static final String ALGORITHM = "Ed25519";
    private static final NamedParameterSpec PARAMETERS = NamedParameterSpec.ED25519;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger FIELD = ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger ORDER = ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D = BigInteger.valueOf(-121665)
        .multiply(BigInteger.valueOf(121666).modInverse(FIELD)).mod(FIELD);
    private static final BigInteger SQRT_EXPONENT = FIELD.subtract(BigInteger.valueOf(5)).shiftRight(3);
    private static final BigInteger SQRT_MINUS_ONE =
        new BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752");

    private Ed25519() {}

    /** Derive the compressed public key from a private seed. */
    public static byte[] publicKey(byte[] seed) throws GeneralSecurityException {
        requireSeed(seed);
        var random = new SeedInput(seed);
        try {
            var generator = KeyPairGenerator.getInstance(ALGORITHM, builtInProvider());
            generator.initialize(PARAMETERS, random);
            var pair = generator.generateKeyPair();
            if (!(pair.getPrivate() instanceof EdECPrivateKey privateKey) ||
                    !(pair.getPublic() instanceof EdECPublicKey publicKey) || !random.used) {
                throw new GeneralSecurityException("Unexpected SunEC seed derivation");
            }
            byte[] derived = privateKey.getBytes().orElseThrow(
                () -> new GeneralSecurityException("SunEC did not return its derived seed"));
            try {
                if (!MessageDigest.isEqual(derived, random.seed)) {
                    throw new GeneralSecurityException("SunEC did not use the supplied Ed25519 seed");
                }
            } finally {
                Arrays.fill(derived, (byte) 0);
            }
            return encode(publicKey.getPoint());
        } finally {
            Arrays.fill(random.seed, (byte) 0);
        }
    }

    public static byte[] sign(byte[] seed, byte[] message) throws GeneralSecurityException {
        requireSeed(seed);
        Provider provider = builtInProvider();
        var factory = KeyFactory.getInstance(ALGORITHM, provider);
        var signer = Signature.getInstance(ALGORITHM, provider);
        signer.initSign(factory.generatePrivate(new EdECPrivateKeySpec(PARAMETERS, seed)));
        signer.update(message);
        return signer.sign();
    }

    /** Check canonical A, R and S, reject small-order A and R, then verify. */
    public static boolean verifyStrict(byte[] publicKey, byte[] message, byte[] signature)
            throws GeneralSecurityException {
        if (publicKey.length != PUBLIC_BYTES || signature.length != SIGNATURE_BYTES) {
            return false;
        }
        byte[] wire = signature.clone();
        EdECPoint point = decode(publicKey);
        if (point == null || scalar(wire, PUBLIC_BYTES, false).compareTo(ORDER) >= 0 || decode(wire) == null) {
            return false;
        }
        Provider provider = builtInProvider();
        var factory = KeyFactory.getInstance(ALGORITHM, provider);
        var verifier = Signature.getInstance(ALGORITHM, provider);
        try {
            verifier.initVerify(factory.generatePublic(new EdECPublicKeySpec(PARAMETERS, point)));
            verifier.update(message);
            return verifier.verify(wire);
        } catch (InvalidKeyException | SignatureException rejected) {
            return false;
        }
    }

    private static EdECPoint decode(byte[] wire) {
        byte[] encoded = Arrays.copyOf(wire, PUBLIC_BYTES);
        boolean odd = (encoded[PUBLIC_BYTES - 1] & 128) != 0;
        BigInteger y = scalar(encoded, 0, true);
        if (y.compareTo(FIELD) >= 0) {
            return null;
        }
        BigInteger y2 = mul(y, y);
        BigInteger u = y2.subtract(ONE).mod(FIELD);
        BigInteger v = mul(D, y2).add(ONE).mod(FIELD);
        BigInteger v3 = mul(mul(v, v), v);
        BigInteger v7 = mul(mul(v3, v3), v);
        BigInteger x = mul(mul(u, v3), mul(u, v7).modPow(SQRT_EXPONENT, FIELD));
        BigInteger check = mul(v, mul(x, x));
        if (!check.equals(u)) {
            if (check.add(u).mod(FIELD).signum() != 0) {
                return null;
            }
            x = mul(x, SQRT_MINUS_ONE);
        }
        if ((odd && x.signum() == 0) || smallOrder(x, y)) {
            return null;
        }
        return new EdECPoint(odd, y);
    }

    private static boolean smallOrder(BigInteger x, BigInteger y) {
        // Either square root of x² gives the same cofactor identity result.
        Point p = new Point(x, y, ONE, mul(x, y));
        for (int i = 0; i < 3; i++) {
            p = p.twice();
        }
        return p.x.signum() == 0 && p.y.equals(p.z);
    }

    private record Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t) {
        Point twice() {
            BigInteger minus = y.subtract(x);
            BigInteger plus = y.add(x);
            BigInteger a = mul(minus, minus);
            BigInteger b = mul(plus, plus);
            BigInteger c = mul(D, mul(t, t)).shiftLeft(1);
            BigInteger d = mul(z, z).shiftLeft(1);
            BigInteger e = b.subtract(a);
            BigInteger f = d.subtract(c);
            BigInteger g = d.add(c);
            BigInteger h = b.add(a);
            return new Point(mul(e, f), mul(g, h), mul(f, g), mul(e, h));
        }
    }

    private static BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(FIELD);
    }

    private static BigInteger scalar(byte[] source, int offset, boolean clearHighBit) {
        byte[] reversed = new byte[PUBLIC_BYTES];
        for (int i = 0; i < PUBLIC_BYTES; i++) {
            reversed[i] = source[offset + PUBLIC_BYTES - 1 - i];
        }
        if (clearHighBit) {
            reversed[0] &= 0x7f;
        }
        return new BigInteger(1, reversed);
    }

    private static byte[] encode(EdECPoint point) {
        byte[] bigEndian = point.getY().toByteArray();
        byte[] result = new byte[PUBLIC_BYTES];
        for (int i = 0; i < bigEndian.length; i++) {
            result[i] = bigEndian[bigEndian.length - 1 - i];
        }
        if (point.isXOdd()) {
            result[PUBLIC_BYTES - 1] |= (byte) 0x80;
        }
        return result;
    }

    private static void requireSeed(byte[] seed) {
        if (seed.length != SEED_BYTES) {
            throw new IllegalArgumentException("Ed25519 requires a 32-byte seed");
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

    private static final class SeedInput extends SecureRandom {
        private static final long serialVersionUID = 1L;
        final byte[] seed;
        boolean used;

        SeedInput(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public void nextBytes(byte[] target) {
            if (used || target.length != SEED_BYTES) {
                throw new ProviderException("Unexpected SunEC Ed25519 seed request");
            }
            System.arraycopy(seed, 0, target, 0, SEED_BYTES);
            used = true;
        }

        @Override
        public byte[] generateSeed(int bytes) {
            throw new ProviderException("Unexpected SunEC Ed25519 entropy request");
        }
    }
}

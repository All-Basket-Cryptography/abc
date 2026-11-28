import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.signature.ed25519.Ed25519;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger ORDER = BigInteger.ONE.shiftLeft(252)
        .add(new BigInteger("27742317777372353535851937790883648493"));

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void same(byte[] actual, byte[] expected) {
        require(Arrays.equals(actual, expected), "Ed25519 byte output mismatch");
    }

    private static void invalid(Action action) throws Exception {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid Ed25519 seed width accepted");
    }

    private static byte[] little(BigInteger scalar) {
        byte[] bigEndian = scalar.toByteArray();
        byte[] result = new byte[32];
        for (int i = 0; i < bigEndian.length; i++) {
            result[i] = bigEndian[bigEndian.length - 1 - i];
        }
        return result;
    }

    private static byte[] withPoint(byte[] signature, byte[] r) {
        byte[] result = signature.clone();
        System.arraycopy(r, 0, result, 0, 32);
        return result;
    }

    private static boolean providerVerification(EdECPoint point, byte[] message, byte[] sig) throws Exception {
        var factory = KeyFactory.getInstance("Ed25519", "SunEC");
        var verifier = Signature.getInstance("Ed25519", "SunEC");
        try {
            verifier.initVerify(factory.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point)));
            verifier.update(message);
            return verifier.verify(sig);
        } catch (InvalidKeyException | SignatureException rejected) {
            return false;
        }
    }

    private static int verifyCofactorPolicy() throws Exception {
        byte[] generator = HEX.parseHex("5866666666666666666666666666666666666666666666666666666666666666");
        byte[] identity = new byte[32];
        identity[0] = 1;
        byte[] message = {0, 1, 3};
        byte[] forged = withPoint(new byte[64], generator);
        forged[32] = 1;
        int baselineAcceptances = providerVerification(new EdECPoint(false, BigInteger.ONE), message, forged) ? 1 : 0;
        require(!Ed25519.verifyStrict(identity, message, forged), "Accepted identity verification key");

        var hash = MessageDigest.getInstance("SHA-512");
        hash.update(identity);
        hash.update(generator);
        byte[] digest = hash.digest(message);
        for (int i = 0, j = digest.length - 1; i < j; i++, j--) {
            byte tmp = digest[i];
            digest[i] = digest[j];
            digest[j] = tmp;
        }
        forged = withPoint(new byte[64], identity);
        System.arraycopy(little(new BigInteger(1, digest).mod(ORDER)), 0, forged, 32, 32);
        byte[] beGenerator = new byte[32];
        for (int i = 0; i < generator.length; i++) {
            beGenerator[i] = generator[31 - i];
        }
        if (providerVerification(new EdECPoint(false, new BigInteger(1, beGenerator)), message, forged)) {
            baselineAcceptances++;
        }
        require(!Ed25519.verifyStrict(generator, message, forged), "Accepted identity signature commitment");
        return baselineAcceptances;
    }

    private static int strictPoints() throws Exception {
        byte[] seed = new byte[32];
        byte[] message = {1, 0, 2, 31};
        byte[] publicKey = Ed25519.publicKey(seed);
        byte[] sig = Ed25519.sign(seed, message);
        require(Ed25519.verifyStrict(publicKey, message, sig), "Rejected valid Ed25519 signature");
        require(!Ed25519.verifyStrict(publicKey, new byte[0], sig), "Accepted wrong message");
        require(!Ed25519.verifyStrict(publicKey, message, new byte[63]), "Accepted short signature");
        require(!Ed25519.verifyStrict(new byte[31], message, sig), "Accepted short public key");
        require(!Ed25519.verifyStrict(publicKey, message, new byte[65]), "Accepted long signature");
        require(!Ed25519.verifyStrict(new byte[33], message, sig), "Accepted long public key");
        invalid(() -> Ed25519.publicKey(new byte[31]));
        invalid(() -> Ed25519.sign(new byte[64], message));
        byte[] badS = sig.clone();
        System.arraycopy(little(ORDER), 0, badS, 32, 32);
        require(!Ed25519.verifyStrict(publicKey, message, badS), "Accepted scalar S equal to L");
        Arrays.fill(badS, 32, 64, (byte) 0xff);
        require(!Ed25519.verifyStrict(publicKey, message, badS), "Accepted oversized scalar S");

        byte[] zero = new byte[32];
        byte[] identity = new byte[32];
        identity[0] = 1;
        byte[] y2 = identity.clone();
        y2[0] = 2;
        byte[] y3 = identity.clone();
        y3[0] = 3;
        byte[] order8A = HEX.parseHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
        byte[] order8B = HEX.parseHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
        byte[] minusOne = little(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(20)));
        byte[] noncanonicalY = little(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(16)));

        // Check the prefilter itself as malformed R can also fail the signature equation.
        var decode = Ed25519.class.getDeclaredMethod("decode", byte[].class);
        decode.setAccessible(true);
        Object owner = Modifier.isStatic(decode.getModifiers()) ? null : Ed25519.class.getField("INSTANCE").get(null);
        require(decode.invoke(owner, y3) != null, "Rejected valid y=3 public point");
        byte[][] rejected = {zero, xSign(zero), identity, minusOne,
            order8A, xSign(order8A), order8B, xSign(order8B), xSign(identity), xSign(minusOne),
            y2, noncanonicalY};
        for (byte[] point : rejected) {
            require(decode.invoke(owner, point) == null, "Prefilter accepted " + HEX.formatHex(point));
            require(!Ed25519.verifyStrict(point, message, sig), "Accepted invalid A encoding");
            require(!Ed25519.verifyStrict(publicKey, message, withPoint(sig, point)), "Accepted invalid R encoding");
        }
        return rejected.length;
    }

    private static byte[] xSign(byte[] point) {
        byte[] copy = point.clone();
        copy[31] ^= (byte) 0x80;
        return copy;
    }

    private static void rejectProviderReplacement() throws Exception {
        Provider original = Security.getProvider("SunEC");
        int position = Arrays.asList(Security.getProviders()).indexOf(original) + 1;
        Security.removeProvider("SunEC");
        try {
            Security.insertProviderAt(new Provider("SunEC", "17", "Test shadow provider") {
                private static final long serialVersionUID = 1L;
            }, 1);
            try {
                Ed25519.publicKey(new byte[32]);
            } catch (NoSuchProviderException expected) {
                return;
            }
            throw new AssertionError("Unexpected provider accepted");
        } finally {
            Security.removeProvider("SunEC");
            Security.insertProviderAt(original, position);
        }
    }

    public static void main(String[] args) throws Exception {
        int invalidPoints = strictPoints();
        int baselineAcceptances = verifyCofactorPolicy();
        rejectProviderReplacement();
        int cases = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String row; (row = input.readLine()) != null; cases++) {
                String[] fields = row.split(":", -1);
                byte[] seed = HEX.parseHex(fields[0]);
                byte[] message = HEX.parseHex(fields[1]);
                byte[] publicKey = HEX.parseHex(fields[2]);
                byte[] signature = HEX.parseHex(fields[3]);
                same(Ed25519.publicKey(seed), publicKey);
                same(Ed25519.sign(seed, message), signature);
                require(Ed25519.verifyStrict(publicKey, message, signature), "Rejected independent valid signature");
                same(seed, HEX.parseHex(fields[0]));
                same(message, HEX.parseHex(fields[1]));
            }
        }
        System.out.println("cases=" + cases);
        System.out.println("invalid_points=" + invalidPoints);
        System.out.println("strict_identity_rejections=2");
        System.out.println("provider_identity_acceptances=" + baselineAcceptances);
        System.out.println("provider_replacements_rejected=1");
    }
}

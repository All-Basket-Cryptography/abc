import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.signature.ecdsap256sha256.EcdsaP256Sha256;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();
    private static final String ORDER_HEX = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    private static final byte[] ORDER = HEX.parseHex(ORDER_HEX);
    private static final byte[] PRIVATE = HEX.parseHex(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");

    private static void require(boolean condition, String failure) {
        if (!condition) {
            throw new AssertionError(failure);
        }
    }

    private static void reject(Runnable call) {
        try {
            call.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid P-256 scalar accepted");
    }

    private static byte[] alternateS(byte[] signature) {
        byte[] changed = signature.clone();
        byte[] value = new BigInteger(1, ORDER).subtract(new BigInteger(1, signature, 32, 32)).toByteArray();
        int copied = Math.min(32, value.length);
        Arrays.fill(changed, 32, 64, (byte) 0);
        System.arraycopy(value, value.length - copied, changed, 64 - copied, copied);
        return changed;
    }

    private static void vectors() {
        byte[] publicKey = EcdsaP256Sha256.publicKey(PRIVATE);
        require(HEX.formatHex(publicKey).equals("0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"), "RFC public key");
        byte[] compressed = Arrays.copyOf(publicKey, 33);
        compressed[0] = 3;
        String[] messages = {"sample", "test"};
        String[] expected = {
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" +
            "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
        };
        for (int i = 0; i < messages.length; i++) {
            byte[] message = messages[i].getBytes(StandardCharsets.US_ASCII);
            byte[] signature = EcdsaP256Sha256.sign(PRIVATE, message);
            require(HEX.formatHex(signature).equals(expected[i]), "RFC SHA-256 P1363 signature");
            require(EcdsaP256Sha256.verify(publicKey, message, signature), "RFC uncompressed verify");
            require(EcdsaP256Sha256.verify(compressed, message, signature), "RFC compressed verify");
            require(EcdsaP256Sha256.verify(publicKey, message, alternateS(signature)), "Alternate S rejected");
        }
    }

    private static void malformed() {
        byte[] msg = {0, 1, 2};
        byte[] pub = EcdsaP256Sha256.publicKey(PRIVATE);
        byte[] sig = EcdsaP256Sha256.sign(PRIVATE, msg);
        byte[] allOnes = new byte[32];
        Arrays.fill(allOnes, (byte) 0xff);
        for (byte[] scalar : new byte[][] {new byte[31], new byte[33], new byte[32], ORDER, allOnes}) {
            reject(() -> EcdsaP256Sha256.publicKey(scalar));
            reject(() -> EcdsaP256Sha256.sign(scalar, msg));
        }
        byte[] hybrid = pub.clone();
        hybrid[0] = 7;
        byte[] nonCurve = new byte[65];
        nonCurve[0] = 4;
        byte[] noncanonicalX = new byte[33];
        noncanonicalX[0] = 2;
        System.arraycopy(allOnes, 0, noncanonicalX, 1, allOnes.length);
        for (byte[] invalid : new byte[][] {new byte[0], new byte[1], Arrays.copyOf(pub, 64), hybrid,
                                            nonCurve, noncanonicalX}) {
            require(!EcdsaP256Sha256.verify(invalid, msg, sig), "Invalid SEC 1 point accepted");
        }
        for (int offset : new int[] {0, 32}) {
            byte[] invalid = sig.clone();
            Arrays.fill(invalid, offset, offset + 32, (byte) 0);
            require(!EcdsaP256Sha256.verify(pub, msg, invalid), "Zero signature component accepted");
            System.arraycopy(ORDER, 0, invalid, offset, 32);
            require(!EcdsaP256Sha256.verify(pub, msg, invalid), "Component equal to n accepted");
        }
        require(!EcdsaP256Sha256.verify(pub, msg, Arrays.copyOf(sig, 63)), "Truncated signature accepted");
        require(!EcdsaP256Sha256.verify(pub, msg, Arrays.copyOf(sig, 65)), "Extended signature accepted");
        require(!EcdsaP256Sha256.verify(pub, new byte[0], sig), "Changed message accepted");
        sig[63] ^= 1;
        require(!EcdsaP256Sha256.verify(pub, msg, sig), "Changed signature accepted");
    }

    public static void main(String[] args) throws Exception {
        boolean sign = args[0].equals("sign");
        if (sign) {
            vectors();
            malformed();
        }
        int cases = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String line; (line = input.readLine()) != null; cases++) {
                String[] row = line.split(":", -1);
                if (sign) {
                    byte[] scalar = HEX.parseHex(row[0]);
                    byte[] message = HEX.parseHex(row[1]);
                    byte[] signature = EcdsaP256Sha256.sign(scalar, message);
                    require(Arrays.equals(signature, EcdsaP256Sha256.sign(scalar, message)), "Nondeterministic signing");
                    System.out.println(HEX.formatHex(EcdsaP256Sha256.publicKey(scalar)) + ":" + HEX.formatHex(signature));
                } else {
                    byte[] msg = HEX.parseHex(row[0]);
                    byte[] signature = HEX.parseHex(row[3]);
                    require(EcdsaP256Sha256.verify(HEX.parseHex(row[1]), msg, signature), "OpenSSL uncompressed verify");
                    require(EcdsaP256Sha256.verify(HEX.parseHex(row[2]), msg, signature), "OpenSSL compressed verify");
                }
            }
        }
        if (!sign) {
            System.out.println(cases);
        }
    }
}

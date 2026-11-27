package org.allbasket.abc.kdf.pbkdf2sha256;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Pbkdf2Sha256Checks {
    private static final HexFormat HEX = HexFormat.of();

    private static void require(boolean passed, String message) {
        if (!passed) {
            throw new AssertionError(message);
        }
    }

    private static byte[] reference(byte[] password, byte[] salt, int rounds, int size)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(password.length == 0 ? new byte[32] : password, "HmacSHA256"));
        ByteBuffer output = ByteBuffer.allocate(size);
        ByteBuffer index = ByteBuffer.allocate(4);
        for (int i = 1; output.hasRemaining(); i++) {
            mac.update(salt);
            byte[] previous = mac.doFinal(index.putInt(0, i).array());
            byte[] block = previous.clone();
            for (int round = 1; round < rounds; round++) {
                previous = mac.doFinal(previous);
                for (int j = 0; j < block.length; j++) {
                    block[j] ^= previous[j];
                }
            }
            output.put(block, 0, Math.min(output.remaining(), block.length));
        }
        return output.array();
    }

    private static byte[] ascii(String str) {
        return str.getBytes(StandardCharsets.US_ASCII);
    }

    private static void check(byte[] password, byte[] salt, int rounds, byte[] expected) {
        require(Arrays.equals(Pbkdf2Sha256.derive(password, salt, rounds, expected.length), expected),
            "PBKDF2 result");
    }

    private static void reject(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected invalid PBKDF2 argument");
        } catch (IllegalArgumentException expected) {
            // Expected API rejection.
        }
    }

    public static void main(String[] args) throws GeneralSecurityException {
        check(ascii("passwd"), ascii("salt"), 1, HEX.parseHex(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
        check(ascii("Password"), ascii("NaCl"), 80_000, HEX.parseHex(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" +
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"));
        Random random = new Random(8018);
        int comparisons = 0;
        for (int size : new int[]{1, 31, 32, 33, 63, 64, 65, 95, 257}) {
            for (int passwordSize : new int[]{0, 1, 64, 65, 4096}) {
                byte[] password = new byte[passwordSize];
                byte[] salt = new byte[size % 97];
                random.nextBytes(password);
                random.nextBytes(salt);
                int rounds = size % 17 + 1;
                check(password, salt, rounds, reference(password, salt, rounds, size));
                ++comparisons;
            }
        }
        byte[] empty = {};
        reject(() -> Pbkdf2Sha256.derive(empty, empty, 0, 1));
        reject(() -> Pbkdf2Sha256.derive(empty, empty, 1, 0));
        reject(() -> Pbkdf2Sha256.derive(empty, empty, Pbkdf2Sha256.MAX_ITERATIONS + 1, 1));
        System.out.printf("{\"known_answers\":2,\"comparisons\":%d,\"rejects_invalid_lengths\":true}%n",
            comparisons);
    }
}

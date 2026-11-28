package org.allbasket.abc.kdf.hkdfsha256;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class HkdfSha256Checks {
    private static final HexFormat HEX = HexFormat.of();
    private static final int TAG_SIZE = 32;

    private static void require(boolean passed, String message) {
        if (!passed) {
            throw new AssertionError(message);
        }
    }

    private static Mac referenceMac(byte[] key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key == null || key.length == 0 ? new byte[TAG_SIZE] : key, "HmacSHA256"));
        return mac;
    }

    private static byte[] referenceExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        Mac mac = referenceMac(prk);
        for (int i = 1, written = 0; written < length; i++) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) i);
            previous = mac.doFinal();
            int count = Math.min(length - written, previous.length);
            System.arraycopy(previous, 0, output, written, count);
            written += count;
        }
        return output;
    }

    private static void check(byte[] salt, byte[] ikm, byte[] info, byte[] expectedPrk, byte[] expected) {
        byte[] prk = HkdfSha256.extract(salt, ikm);
        require(Arrays.equals(prk, expectedPrk), "extract");
        require(Arrays.equals(HkdfSha256.expand(prk, info, expected.length), expected), "expand");
        require(Arrays.equals(HkdfSha256.derive(salt, ikm, info, expected.length), expected), "derive");
    }

    private static byte[] random(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static void reject(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected invalid HKDF argument");
        } catch (IllegalArgumentException expected) {
            // Expected API rejection.
        }
    }

    public static void main(String[] args) throws GeneralSecurityException {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        check(HEX.parseHex("000102030405060708090a0b0c"), ikm, HEX.parseHex("f0f1f2f3f4f5f6f7f8f9"),
            HEX.parseHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
            HEX.parseHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
        check(null, ikm, new byte[0],
            HEX.parseHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
            HEX.parseHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
        Random random = new Random(5869);
        int comparisons = 0;
        for (int saltLength : new int[]{0, 1, 32, 64, 65, 129}) {
            for (int size : new int[]{0, 1, 31, 32, 33, 63, 64, 65, 127, 8159, 8160}) {
                byte[] salt = random(random, saltLength);
                byte[] input = random(random, size % 101);
                byte[] info = random(random, size % 131);
                byte[] prk = referenceMac(salt).doFinal(input);
                check(salt, input, info, prk, referenceExpand(prk, info, size));
                ++comparisons;
            }
        }
        for (int length : new int[]{33, 64, 65, 131}) {
            byte[] prk = random(random, length);
            byte[] info = random(random, 65);
            require(Arrays.equals(HkdfSha256.expand(prk, info, 257), referenceExpand(prk, info, 257)),
                "long PRK");
            ++comparisons;
        }
        reject(() -> HkdfSha256.expand(new byte[31], new byte[0], 1));
        reject(() -> HkdfSha256.expand(new byte[32], new byte[0], -1));
        reject(() -> HkdfSha256.derive(null, new byte[0], new byte[0], HkdfSha256.MAX_OUTPUT_BYTES + 1));
        System.out.printf("{\"known_answers\":2,\"comparisons\":%d,\"rejects_invalid_lengths\":true}%n", comparisons);
    }
}

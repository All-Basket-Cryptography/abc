package org.allbasket.abc.mac.hmacsha256;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class HmacSha256Checks {
    private static final HexFormat HEX = HexFormat.of();

    private static void require(boolean passed, String message) {
        if (!passed) {
            throw new AssertionError(message);
        }
    }

    private static byte[] reference(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        // The JCA provider rejects an empty SecretKeySpec. Zero padding gives the same block.
        mac.init(new SecretKeySpec(key.length == 0 ? new byte[64] : key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static void check(byte[] key, byte[] input, byte[] tag) throws GeneralSecurityException {
        require(Arrays.equals(HmacSha256.authenticate(key, input), tag), "one-shot tag");
        HmacSha256 stream = new HmacSha256(key);
        int half = input.length / 2;
        byte[] expectedPrefix = reference(key, Arrays.copyOf(input, half));
        Arrays.fill(key, (byte) 0xa5);
        stream.update(input, 0, half);
        require(Arrays.equals(stream.digest(), expectedPrefix), "prefix snapshot");
        try {
            stream.update(input, 0, input.length + 1);
            throw new AssertionError("invalid range accepted");
        } catch (IndexOutOfBoundsException expected) {
            require(Arrays.equals(stream.digest(), expectedPrefix), "range rejection changed state");
        }
        stream.update(input, half, input.length - half);
        require(Arrays.equals(stream.digest(), tag), "streaming tag");
        byte[] saved = stream.digest();
        Arrays.fill(saved, (byte) 0);
        require(Arrays.equals(stream.digest(), tag), "snapshot must not expose state");
    }

    private static byte[] repeat(int size, int value) {
        byte[] bytes = new byte[size];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static byte[] ascii(String string) {
        return string.getBytes(StandardCharsets.US_ASCII);
    }

    public static void main(String[] args) throws GeneralSecurityException {
        check(repeat(20, 0x0b), ascii("Hi There"),
            HEX.parseHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
        check(ascii("Jefe"), ascii("what do ya want for nothing?"),
            HEX.parseHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        check(repeat(131, 0xaa), ascii("Test Using Larger Than Block-Size Key - Hash Key First"),
            HEX.parseHex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
        Random random = new Random(4231);
        int comparisons = 0;
        for (int keyLength : new int[]{0, 1, 31, 32, 63, 64, 65, 131, 1024}) {
            for (int length : new int[]{0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 257, 1024}) {
                byte[] key = new byte[keyLength];
                byte[] input = new byte[length];
                random.nextBytes(key);
                random.nextBytes(input);
                check(key, input, reference(key, input));
                ++comparisons;
            }
        }
        System.out.printf("{\"known_answers\":3,\"comparisons\":%d,\"streaming\":true,\"range_atomicity\":true}%n",
            comparisons);
    }
}

package org.allbasket.abc.hash.sha512;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/** Separate packaged-JAR consumer and differential check. */
public final class Sha512Checks {
    private static final HexFormat HEX = HexFormat.of();

    private Sha512Checks() {}

    private static void require(boolean passed, String message) {
        if (!passed) {
            throw new AssertionError(message);
        }
    }

    private static byte[] reference(MessageDigest oracle, byte[] input, int prefix) {
        oracle.update(input, 0, prefix);
        return oracle.digest();
    }

    private static int compare(MessageDigest oracle, byte[] input, Random random) {
        byte[] expected = reference(oracle, input, input.length);
        require(Arrays.equals(Sha512.hash(input), expected), "One-shot mismatch");
        byte[] framed = new byte[input.length + 2];
        Arrays.fill(framed, (byte) 0x5a);
        System.arraycopy(input, 0, framed, 1, input.length);

        Sha512 stream = new Sha512().update(framed, 1, 0);
        require(Arrays.equals(stream.digest(), reference(oracle, input, 0)), "Empty update");
        int snapshots = 1;
        int offset = 0;
        int chunkLimit = input.length <= 257 ? 32 : 8192;
        while (offset < input.length) {
            int count = Math.min(input.length - offset, 1 + random.nextInt(chunkLimit));
            stream.update(framed, 1 + offset, count);
            offset += count;
            require(Arrays.equals(stream.digest(), reference(oracle, input, offset)), "Streaming prefix mismatch");
            snapshots++;
        }
        stream.update(framed, framed.length, 0);
        require(Arrays.equals(stream.digest(), expected), "Empty update changed digest");
        require(framed[0] == (byte) 0x5a && framed[framed.length - 1] == (byte) 0x5a, "Input changed");
        return snapshots;
    }

    private static void knownAnswer(byte[] input, String expected) {
        require(Arrays.equals(Sha512.hash(input), HEX.parseHex(expected)), "Known answer mismatch");
    }

    private static void rejectRange(Sha512 stream, byte[] input, int offset, int length, byte[] expected) {
        try {
            stream.update(input, offset, length);
            throw new AssertionError("Invalid range accepted");
        } catch (IndexOutOfBoundsException safe) {
            require(Arrays.equals(stream.digest(), expected), "Range rejection changed streaming state");
        }
    }

    private static void checkRangesAndOwnership(MessageDigest oracle) {
        byte[] input = "abc".getBytes(StandardCharsets.US_ASCII);
        Sha512 stream = new Sha512().update(input, 0, 2);
        byte[] prefix = reference(oracle, input, 2);
        rejectRange(stream, input, -1, 1, prefix);
        rejectRange(stream, input, 0, -1, prefix);
        rejectRange(stream, input, 1, Integer.MAX_VALUE, prefix);
        rejectRange(stream, input, input.length + 1, 0, prefix);
        stream.update(input, 2, 1);
        byte[] expected = reference(oracle, input, input.length);
        Arrays.fill(input, (byte) 0);
        Arrays.fill(stream.digest(), (byte) 0);
        require(Arrays.equals(stream.digest(), expected), "Caller array aliased state");
    }

    private static BigInteger limbs(long high, long low) {
        return new BigInteger(1, ByteBuffer.allocate(16).putLong(high).putLong(low).array());
    }

    private static void checkEncodedCount(long high, long low, int incoming) {
        BigInteger expected = limbs(high, low).add(BigInteger.valueOf(incoming));
        long nextLow = low + incoming;
        long nextHigh;
        try {
            nextHigh = Sha512.checkedLengthHigh(high, low, nextLow);
        } catch (IllegalArgumentException rejected) {
            require(expected.bitLength() > 125, "Accepted count rejected");
            return;
        }
        require(expected.bitLength() <= 125 && limbs(nextHigh, nextLow).equals(expected), "Length carry mismatch");
        byte[] encoded = new byte[18];
        encoded[0] = 0x5a;
        encoded[17] = 0x5a;
        Sha512.writeBitLength(encoded, 1, nextHigh, nextLow);
        BigInteger bits = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 17));
        require(bits.equals(expected.shiftLeft(3)), "128-bit big-endian bit length mismatch");
        require(encoded[0] == (byte) 0x5a && encoded[17] == (byte) 0x5a, "Length write exceeded its range");
    }

    public static void main(String[] args) throws Exception {
        require(Runtime.version().feature() == 17, "The qualification requires JDK 17");
        MessageDigest oracle = MessageDigest.getInstance("SHA-512");
        byte[] empty = new byte[0];
        byte[] abc = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] million = new byte[1_000_000];
        Arrays.fill(million, (byte) 'a');
        knownAnswer(empty, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        knownAnswer(abc, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        knownAnswer(million, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebd"
            + "e0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");

        Random random = new Random(512);
        int snapshots = compare(oracle, empty, random) + compare(oracle, abc, random) + compare(oracle, million, random);
        int[] boundaries = {0, 1, 7, 8, 55, 56, 63, 64, 110, 111, 112, 113, 127, 128, 129,
            238, 239, 240, 241, 255, 256, 257, 1024, 4096, 65537, 1048576};
        for (int length : boundaries) {
            byte[] input = new byte[length];
            random.nextBytes(input);
            snapshots += compare(oracle, input, random);
        }
        for (int index = 0; index < 128; index++) {
            byte[] input = new byte[random.nextInt(8193)];
            random.nextBytes(input);
            snapshots += compare(oracle, input, random);
        }

        checkRangesAndOwnership(oracle);
        long maxHigh = (1L << 61) - 1;
        checkEncodedCount(maxHigh, -2L, 1);
        checkEncodedCount(maxHigh, -1L, 0);
        checkEncodedCount(maxHigh, -1L, 1);
        checkEncodedCount(maxHigh, -2L, 2);
        checkEncodedCount(maxHigh - 1, -1L, 1);
        for (int index = 0; index < 1000; index++) {
            long high = random.nextLong() & maxHigh;
            long low = index % 2 == 0 ? -32L : random.nextLong();
            checkEncodedCount(high, low, random.nextInt(256));
        }
        System.out.println("runtime=" + Runtime.version());
        System.out.println("architecture=" + System.getProperty("os.arch"));
        System.out.println("oracle=" + oracle.getProvider().getName() + " " + oracle.getProvider().getVersionStr());
        System.out.println("known_answers=3");
        System.out.println("one_shot_comparisons=" + (3 + boundaries.length + 128));
        System.out.println("streaming_snapshots=" + snapshots);
        System.out.println("length_counter_cases=1005");
        System.out.println("range_and_ownership=passed");
    }
}

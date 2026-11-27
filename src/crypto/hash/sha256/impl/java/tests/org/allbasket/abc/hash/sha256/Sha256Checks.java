package org.allbasket.abc.hash.sha256;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/** Standalone consumer of the compiled Java research JAR. */
public final class Sha256Checks {
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] ABC = "abc".getBytes(StandardCharsets.US_ASCII);

    private Sha256Checks() {}

    private static void require(boolean condition, String description) {
        if (!condition) {
            throw new AssertionError(description);
        }
    }

    private static void requireEqual(byte[] actual, byte[] expected, String description) {
        require(Arrays.equals(actual, expected), description);
    }

    private static byte[] reference(MessageDigest oracle, byte[] message, int size) {
        oracle.update(message, 0, size);
        return oracle.digest();
    }

    private static int compare(MessageDigest oracle, byte[] message, Random random) {
        byte[] expected = reference(oracle, message, message.length);
        requireEqual(Sha256.hash(message), expected, "one-shot mismatch at length " + message.length);

        byte[] input = new byte[message.length + 2];
        input[0] = (byte) 0xa5;
        input[input.length - 1] = (byte) 0x5a;
        System.arraycopy(message, 0, input, 1, message.length);
        Sha256 streaming = new Sha256();
        requireEqual(streaming.update(input, 1, 0).digest(), reference(oracle, message, 0),
            "empty update mismatch");
        int snapshots = 1;
        int chunkLimit = message.length <= 257 ? 32 : 8192;
        for (int offset = 0; offset < message.length;) {
            int chunk = Math.min(message.length - offset, random.nextInt(chunkLimit) + 1);
            streaming.update(input, offset + 1, chunk);
            offset += chunk;
            requireEqual(streaming.digest(), reference(oracle, message, offset),
                "streaming snapshot mismatch at prefix " + offset + " of " + message.length);
            snapshots++;
        }
        requireEqual(streaming.update(input, input.length, 0).digest(), expected,
            "empty update changed completed state");
        require(input[0] == (byte) 0xa5 && input[input.length - 1] == (byte) 0x5a,
            "hash changed surrounding input bytes");
        return snapshots;
    }

    private static void expect(Class<? extends RuntimeException> error, Runnable operation) {
        try {
            operation.run();
        } catch (RuntimeException failure) {
            require(error.isInstance(failure), "unexpected error type: " + failure.getClass().getName());
            return;
        }
        throw new AssertionError("invalid input was accepted");
    }

    private static void checkOwnershipAndValidation() {
        Sha256 state = new Sha256().update(ABC, 0, 2);
        byte[] before = state.digest();
        expect(IndexOutOfBoundsException.class, () -> state.update(ABC, -1, 2));
        expect(IndexOutOfBoundsException.class, () -> state.update(ABC, 0, -1));
        expect(IndexOutOfBoundsException.class, () -> state.update(ABC, 1, Integer.MAX_VALUE));
        expect(IndexOutOfBoundsException.class, () -> state.update(ABC, ABC.length + 1, 0));
        expect(NullPointerException.class, () -> state.update(null, 0, 0));
        requireEqual(state.digest(), before, "invalid inputs changed stream state");
        requireEqual(state.update(ABC, 2, 1).digest(), Sha256.hash(ABC),
            "stream could not continue after validation errors");

        byte[] mutableInput = Arrays.copyOf(ABC, ABC.length);
        Sha256 owned = new Sha256().update(mutableInput);
        mutableInput[0] ^= 1;
        byte[] mutableOutput = owned.digest();
        mutableOutput[0] ^= 1;
        requireEqual(owned.digest(), Sha256.hash(ABC), "caller arrays aliased internal state");

        long maximum = Sha256.MAX_MESSAGE_BYTES;
        require(Sha256.checkedLength(maximum, 0) == maximum, "zero-length update at limit");
        require(Sha256.checkedLength(maximum - 1, 1) == maximum, "last byte was rejected");
        expect(IllegalArgumentException.class, () -> Sha256.checkedLength(maximum, 1));
        expect(IllegalArgumentException.class, () -> Sha256.checkedLength(maximum - 1, 2));
    }

    public static void main(String[] args) throws Exception {
        require(Runtime.version().feature() == 17, "the qualification run requires JDK 17");
        MessageDigest oracle = MessageDigest.getInstance("SHA-256");
        byte[] millionAs = new byte[1_000_000];
        Arrays.fill(millionAs, (byte) 'a');
        byte[][] knownMessages = {new byte[0], ABC, millionAs};
        String[] knownDigests = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        };
        Random random = new Random(551);
        int snapshots = 0;
        for (int i = 0; i < knownMessages.length; i++) {
            requireEqual(Sha256.hash(knownMessages[i]), HEX.parseHex(knownDigests[i]), "known-answer mismatch " + i);
            snapshots += compare(oracle, knownMessages[i], random);
        }

        int[] lengths = {0, 1, 7, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129,
                         255, 256, 257, 1024, 4096, 65537, 1048576};
        for (int length : lengths) {
            byte[] message = new byte[length];
            random.nextBytes(message);
            snapshots += compare(oracle, message, random);
        }
        int randomCases = 128;
        for (int i = 0; i < randomCases; i++) {
            byte[] message = new byte[random.nextInt(8193)];
            random.nextBytes(message);
            snapshots += compare(oracle, message, random);
        }
        checkOwnershipAndValidation();
        System.out.println("runtime=" + Runtime.version());
        System.out.println("vendor=" + System.getProperty("java.vendor"));
        System.out.println("architecture=" + System.getProperty("os.arch"));
        System.out.println("oracle=" + oracle.getProvider().getName() + " " + oracle.getProvider().getVersionStr());
        System.out.println("known_answers=" + knownDigests.length);
        System.out.println("one_shot_comparisons=" + (knownMessages.length + lengths.length + randomCases));
        System.out.println("streaming_snapshots=" + snapshots);
        System.out.println("error_and_ownership_checks=passed");
    }
}

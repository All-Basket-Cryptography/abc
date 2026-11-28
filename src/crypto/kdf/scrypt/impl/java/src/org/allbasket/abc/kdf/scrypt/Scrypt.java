package org.allbasket.abc.kdf.scrypt;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import org.allbasket.abc.kdf.pbkdf2sha256.Pbkdf2Sha256;

/** RFC 7914 byte-oriented scrypt with a caller-specified memory limit. */
public final class Scrypt {
    private static final int MAX_ARRAY_BYTES = Integer.MAX_VALUE - 8;
    private static final int STATE_WORDS = 16;
    private static final VarHandle WORD =
        MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

    private Scrypt() {}

    /** Return the combined byte count of the primary work arrays. */
    public static int workspaceSize(int cost, int blockSize, int parallel) {
        return layout(cost, blockSize, parallel).workspace;
    }

    /** Derive an owned result, validating the work-array and output budget first. */
    public static byte[] derive(byte[] password, byte[] salt, int cost, int blockSize,
            int parallel, int length, long memoryLimit) {
        Layout sizes = layout(cost, blockSize, parallel);
        if (length < 1 || length > MAX_ARRAY_BYTES) {
            throw new IllegalArgumentException("scrypt requires a positive representable output length");
        }
        if (memoryLimit < (long) sizes.workspace + length) {
            throw new IllegalArgumentException("scrypt work arrays and output exceed the memory limit");
        }
        int[] history = new int[sizes.table / Integer.BYTES];
        int[] lane = new int[sizes.stride / Integer.BYTES];
        int[] reordered = new int[lane.length];
        int[] state = new int[STATE_WORDS];
        int[] scratch = new int[STATE_WORDS];
        byte[] data = Pbkdf2Sha256.derive(password, salt, 1, sizes.lanes);
        try {
            for (int offset = 0; offset < data.length; offset += sizes.stride) {
                for (int i = 0; i < lane.length; i++) {
                    lane[i] = (int) WORD.get(data, offset + i * Integer.BYTES);
                }
                romix(lane, reordered, history, state, scratch, cost);
                for (int i = 0; i < lane.length; i++) {
                    WORD.set(data, offset + i * Integer.BYTES, lane[i]);
                }
            }
            return Pbkdf2Sha256.derive(password, data, 1, length);
        } finally {
            Arrays.fill(data, (byte) 0);
            Arrays.fill(history, 0);
            Arrays.fill(lane, 0);
            Arrays.fill(reordered, 0);
            Arrays.fill(state, 0);
            Arrays.fill(scratch, 0);
        }
    }

    private record Layout(int stride, int lanes, int table, int workspace) {}

    private static Layout layout(int cost, int blockSize, int parallel) {
        if (cost < 2 || blockSize < 1 || parallel < 1 || (cost & (cost - 1)) != 0 ||
                Integer.numberOfTrailingZeros(cost) >= 16L * blockSize) {
            throw new IllegalArgumentException("scrypt requires positive r and p and power-of-two N below 2^(16r)");
        }
        long stride = 128L * blockSize;
        if (stride > MAX_ARRAY_BYTES / cost || stride > MAX_ARRAY_BYTES / parallel) {
            throw new IllegalArgumentException("scrypt work arrays exceed the JVM profile size");
        }
        long lanes = stride * parallel;
        long table = stride * cost;
        long workspace = table + lanes + 2 * stride + 128;
        if (workspace > MAX_ARRAY_BYTES) {
            throw new IllegalArgumentException("scrypt work arrays exceed the JVM profile size");
        }
        return new Layout((int) stride, (int) lanes, (int) table, (int) workspace);
    }

    private static void romix(int[] input, int[] reordered, int[] history, int[] state, int[] scratch, int cost) {
        int[] lane = input;
        int[] next = reordered;
        int words = input.length;
        for (int i = 0; i < cost; i++) {
            System.arraycopy(lane, 0, history, i * words, words);
            blockMix(lane, next, state, scratch);
            int[] previous = lane;
            lane = next;
            next = previous;
        }
        for (int i = 0; i < cost; i++) {
            // N fits in one word, so only the low word of Integerify is needed.
            int slot = (lane[words - STATE_WORDS] & (cost - 1)) * words;
            for (int j = 0; j < words; j++) {
                lane[j] ^= history[slot + j];
            }
            blockMix(lane, next, state, scratch);
            int[] previous = lane;
            lane = next;
            next = previous;
        }
        // The 2*N exchanges place the final result back in input.
    }

    private static void blockMix(int[] input, int[] output, int[] state, int[] scratch) {
        int blocks = input.length / STATE_WORDS;
        System.arraycopy(input, input.length - STATE_WORDS, state, 0, STATE_WORDS);
        for (int block = 0; block < blocks; block++) {
            int offset = block * STATE_WORDS;
            for (int i = 0; i < STATE_WORDS; i++) {
                state[i] ^= input[offset + i];
            }
            salsa8(state, scratch);
            int position = (block / 2 + (block & 1) * (blocks / 2)) * STATE_WORDS;
            System.arraycopy(state, 0, output, position, STATE_WORDS);
        }
    }

    private static void salsa8(int[] state, int[] scratch) {
        System.arraycopy(state, 0, scratch, 0, STATE_WORDS);
        for (int i = 0; i < 4; i++) {
            quarter(scratch, 0, 4, 8, 12);
            quarter(scratch, 5, 9, 13, 1);
            quarter(scratch, 10, 14, 2, 6);
            quarter(scratch, 15, 3, 7, 11);
            quarter(scratch, 0, 1, 2, 3);
            quarter(scratch, 5, 6, 7, 4);
            quarter(scratch, 10, 11, 8, 9);
            quarter(scratch, 15, 12, 13, 14);
        }
        for (int i = 0; i < STATE_WORDS; i++) {
            state[i] += scratch[i];
        }
    }

    private static void quarter(int[] words, int a, int b, int c, int d) {
        words[b] ^= Integer.rotateLeft(words[a] + words[d], 7);
        words[c] ^= Integer.rotateLeft(words[b] + words[a], 9);
        words[d] ^= Integer.rotateLeft(words[c] + words[b], 13);
        words[a] ^= Integer.rotateLeft(words[d] + words[c], 18);
    }
}

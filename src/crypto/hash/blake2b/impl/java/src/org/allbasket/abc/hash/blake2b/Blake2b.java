package org.allbasket.abc.hash.blake2b;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/** RFC 7693 unkeyed sequential BLAKE2b with a fixed digest size. */
public final class Blake2b {
    public static final int BLOCK_BYTES = 128;
    public static final int MAX_DIGEST_BYTES = 64;

    private static final VarHandle WORD = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
    private static final long[] IV = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
    };
    private static final int[][] SIGMA = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    };

    private final long[] chaining = new long[8];
    private final byte[] pending = new byte[BLOCK_BYTES];
    private final int digestSize;
    private int used;
    private long lengthLow;
    private long lengthHigh;

    public Blake2b(int digestSize) {
        if (digestSize < 1 || digestSize > MAX_DIGEST_BYTES) {
            throw new IllegalArgumentException("BLAKE2b digest size must be between 1 and 64 bytes");
        }
        this.digestSize = digestSize;
        reset();
    }

    public Blake2b() {
        this(MAX_DIGEST_BYTES);
    }

    public void reset() {
        System.arraycopy(IV, 0, chaining, 0, IV.length);
        chaining[0] ^= 0x01010000L | digestSize;
        Arrays.fill(pending, (byte) 0);
        lengthLow = 0;
        lengthHigh = 0;
        used = 0;
    }

    public void update(byte[] input) {
        update(input, 0, input.length);
    }

    public void update(byte[] input, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, input.length);
        long nextLow = lengthLow + length;
        long carry = Long.compareUnsigned(nextLow, lengthLow) < 0 ? 1 : 0;
        if (carry != 0 && lengthHigh == -1L) {
            throw new ArithmeticException("BLAKE2b message exceeds its 128-bit byte counter");
        }
        long compressedLow = lengthLow - used;
        long compressedHigh = lengthHigh - (Long.compareUnsigned(lengthLow, used) < 0 ? 1 : 0);
        lengthLow = nextLow;
        lengthHigh += carry;

        if (length <= BLOCK_BYTES - used) {
            System.arraycopy(input, offset, pending, used, length);
            used += length;
            return;
        }

        // Reuse one scratch pair across all nonfinal blocks in this update.
        long[] words = new long[16];
        long[] mix = new long[16];
        int cursor = offset;
        int end = offset + length;
        if (used != 0) {
            int count = BLOCK_BYTES - used;
            System.arraycopy(input, cursor, pending, used, count);
            cursor += count;
            compressedLow += BLOCK_BYTES;
            if (Long.compareUnsigned(compressedLow, BLOCK_BYTES) < 0) {
                compressedHigh++;
            }
            compress(chaining, pending, 0, compressedLow, compressedHigh, false, words, mix);
        }
        while (end - cursor > BLOCK_BYTES) {
            compressedLow += BLOCK_BYTES;
            if (Long.compareUnsigned(compressedLow, BLOCK_BYTES) < 0) {
                compressedHigh++;
            }
            compress(chaining, input, cursor, compressedLow, compressedHigh, false, words, mix);
            cursor += BLOCK_BYTES;
        }
        used = end - cursor;
        System.arraycopy(input, cursor, pending, 0, used);
    }

    /** Return an owned digest snapshot without closing the absorber. */
    public byte[] digest() {
        byte[] block = pending.clone();
        Arrays.fill(block, used, BLOCK_BYTES, (byte) 0);
        long[] state = chaining.clone();
        compress(state, block, 0, lengthLow, lengthHigh, true, new long[16], new long[16]);
        byte[] output = new byte[digestSize];
        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) (state[i / 8] >>> (8 * (i % 8)));
        }
        return output;
    }

    public static byte[] hash(byte[] input, int digestSize) {
        Blake2b context = new Blake2b(digestSize);
        context.update(input);
        return context.digest();
    }

    private static void compress(long[] state, byte[] input, int offset, long low, long high, boolean last,
                                 long[] words, long[] mix) {
        for (int i = 0; i < words.length; i++) {
            words[i] = (long) WORD.get(input, offset + 8 * i);
        }
        System.arraycopy(state, 0, mix, 0, 8);
        System.arraycopy(IV, 0, mix, 8, 8);
        mix[12] ^= low;
        mix[13] ^= high;
        if (last) {
            mix[14] = ~mix[14];
        }
        for (int round = 0; round < 12; round++) {
            int[] s = SIGMA[round % 10];
            g(mix, 0, 4, 8, 12, words[s[0]], words[s[1]]);
            g(mix, 1, 5, 9, 13, words[s[2]], words[s[3]]);
            g(mix, 2, 6, 10, 14, words[s[4]], words[s[5]]);
            g(mix, 3, 7, 11, 15, words[s[6]], words[s[7]]);
            g(mix, 0, 5, 10, 15, words[s[8]], words[s[9]]);
            g(mix, 1, 6, 11, 12, words[s[10]], words[s[11]]);
            g(mix, 2, 7, 8, 13, words[s[12]], words[s[13]]);
            g(mix, 3, 4, 9, 14, words[s[14]], words[s[15]]);
        }
        for (int i = 0; i < state.length; i++) {
            state[i] ^= mix[i] ^ mix[i + 8];
        }
    }

    private static void g(long[] v, int a, int b, int c, int d, long x, long y) {
        v[a] += v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] += v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] += v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] += v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }
}

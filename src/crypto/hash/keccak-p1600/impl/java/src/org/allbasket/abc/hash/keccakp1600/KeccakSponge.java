package org.allbasket.abc.hash.keccakp1600;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/** Keccak-p[1600,24] and the byte-oriented 1088-bit-rate sponge. */
public final class KeccakSponge {
    public static final int RATE_BYTES = 136;
    private static final VarHandle WORD = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
    private static final int[] ROTATION = {
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
        41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    };
    private static final int[] PI = {
        0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
        23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
    };
    private static final long[] IOTA = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };

    private final long[] lanes = new long[25];
    private final byte[] pending = new byte[RATE_BYTES];
    private int used;

    public void reset() {
        Arrays.fill(lanes, 0);
        Arrays.fill(pending, (byte) 0);
        used = 0;
    }

    public void update(byte[] input, int start, int length) {
        Objects.checkFromIndexSize(start, length, input.length);
        int offset = start;
        int end = start + length;
        if (used != 0) {
            int count = Math.min(end - offset, RATE_BYTES - used);
            System.arraycopy(input, offset, pending, used, count);
            used += count;
            offset += count;
            if (used < RATE_BYTES) {
                return;
            }
            absorb(lanes, pending, 0);
        }
        while (end - offset >= RATE_BYTES) {
            absorb(lanes, input, offset);
            offset += RATE_BYTES;
        }
        used = end - offset;
        System.arraycopy(input, offset, pending, 0, used);
    }

    public byte[] sha3Digest() {
        byte[] digest = new byte[32];
        encode(finish(0x06), digest);
        return digest;
    }

    public Reader shakeReader() {
        return new Reader(finish(0x1f));
    }

    private long[] finish(int suffix) {
        byte[] block = Arrays.copyOf(pending, RATE_BYTES);
        Arrays.fill(block, used, RATE_BYTES, (byte) 0);
        block[used] = (byte) suffix;
        block[RATE_BYTES - 1] |= (byte) 0x80;
        long[] state = lanes.clone();
        absorb(state, block, 0);
        return state;
    }

    private static void absorb(long[] state, byte[] block, int offset) {
        for (int lane = 0; lane < RATE_BYTES / 8; lane++) {
            state[lane] ^= (long) WORD.get(block, offset + 8 * lane);
        }
        permute(state);
    }

    private static void encode(long[] state, byte[] block) {
        for (int lane = 0; lane < block.length / 8; lane++) {
            WORD.set(block, 8 * lane, state[lane]);
        }
    }

    /** Apply the 24 rounds to lanes in x + 5*y order. */
    public static void permute(long[] state) {
        if (state.length != 25) {
            throw new IllegalArgumentException("Keccak-p[1600] requires 25 lanes");
        }
        long[] parity = new long[5];
        long[] theta = new long[5];
        long[] shuffled = new long[25];
        for (long constant : IOTA) {
            for (int x = 0; x < 5; x++) {
                parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                theta[x] = parity[(x + 4) % 5] ^ Long.rotateLeft(parity[(x + 1) % 5], 1);
            }
            for (int source = 0; source < 25; source++) {
                shuffled[PI[source]] = Long.rotateLeft(state[source] ^ theta[source % 5], ROTATION[source]);
            }
            for (int row = 0; row < 25; row += 5) {
                long a = shuffled[row];
                long b = shuffled[row + 1];
                long c = shuffled[row + 2];
                long d = shuffled[row + 3];
                long e = shuffled[row + 4];
                state[row] = a ^ (~b & c);
                state[row + 1] = b ^ (~c & d);
                state[row + 2] = c ^ (~d & e);
                state[row + 3] = d ^ (~e & a);
                state[row + 4] = e ^ (~a & b);
            }
            state[0] ^= constant;
        }
    }

    /** A SHAKE256 snapshot with its own output cursor. */
    public static final class Reader {
        private final long[] lanes;
        private final byte[] block = new byte[RATE_BYTES];
        private int offset;

        private Reader(long[] lanes) {
            this.lanes = lanes;
            encode(lanes, block);
        }

        public byte[] read(int length) {
            if (length < 0) {
                throw new IllegalArgumentException("SHAKE length must be nonnegative");
            }
            byte[] result = new byte[length];
            readInto(result, 0, length);
            return result;
        }

        public void readInto(byte[] output, int start, int length) {
            Objects.checkFromIndexSize(start, length, output.length);
            int end = start + length;
            int cursor = start;
            while (cursor < end) {
                if (offset == RATE_BYTES) {
                    permute(lanes);
                    encode(lanes, block);
                    offset = 0;
                }
                int count = Math.min(end - cursor, RATE_BYTES - offset);
                System.arraycopy(block, offset, output, cursor, count);
                offset += count;
                cursor += count;
            }
        }
    }
}

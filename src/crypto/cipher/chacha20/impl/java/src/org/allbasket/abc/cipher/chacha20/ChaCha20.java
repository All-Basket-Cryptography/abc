package org.allbasket.abc.cipher.chacha20;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/** Byte-oriented IETF ChaCha20 with a 96-bit nonce and a 32-bit block counter. */
public final class ChaCha20 implements AutoCloseable {
    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 12;
    public static final int BLOCK_BYTES = 64;
    private static final long LIMIT = 1L << 32;
    private static final VarHandle WORD =
        MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

    private final int[] initial = new int[16];
    private final int[] work = new int[16];
    private final byte[] stream = new byte[BLOCK_BYTES];
    private long nextCounter;
    private int skip = BLOCK_BYTES;
    private boolean closed;

    public ChaCha20(byte[] key, byte[] nonce, long counter) {
        if (key.length != KEY_BYTES || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("ChaCha20 requires a 32-byte key and 12-byte nonce");
        }
        if (counter < 0 || counter >= LIMIT) {
            throw new IllegalArgumentException("ChaCha20 counter must be an unsigned 32-bit value");
        }
        nextCounter = counter;
        initial[0] = 0x61707865;
        initial[1] = 0x3320646e;
        initial[2] = 0x79622d32;
        initial[3] = 0x6b206574;
        for (int word = 0; word < KEY_BYTES / 4; word++) {
            initial[4 + word] = (int) WORD.get(key, 4 * word);
        }
        for (int word = 0; word < NONCE_BYTES / 4; word++) {
            initial[13 + word] = (int) WORD.get(nonce, 4 * word);
        }
    }

    /** Return the number of unused bytes in the remaining counter interval. */
    public long remaining() {
        if (closed) {
            throw new IllegalStateException("ChaCha20 context is closed");
        }
        return (LIMIT - nextCounter) * BLOCK_BYTES + (BLOCK_BYTES - skip);
    }

    public void apply(byte[] data) {
        apply(data, 0, data.length);
    }

    /** XOR the chosen range in place. A rejected request preserves data and state. */
    public void apply(byte[] data, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, data.length);
        if (length > remaining()) {
            throw new IllegalStateException("ChaCha20 block counter exhausted");
        }
        int end = offset + length;
        int cursor = offset;
        while (cursor < end) {
            if (skip == BLOCK_BYTES) {
                refill();
            }
            int count = Math.min(end - cursor, BLOCK_BYTES - skip);
            for (int i = 0; i < count; i++) {
                data[cursor + i] ^= stream[skip + i];
            }
            cursor += count;
            skip += count;
        }
    }

    /** Return the requested keystream block in an owned byte array. */
    public static byte[] block(byte[] key, byte[] nonce, long counter) {
        try (ChaCha20 state = new ChaCha20(key, nonce, counter)) {
            state.refill();
            return state.stream.clone();
        }
    }

    /** Clear the adapter's working buffers and invalidate the context. */
    @Override
    public void close() {
        Arrays.fill(initial, 0);
        Arrays.fill(work, 0);
        Arrays.fill(stream, (byte) 0);
        nextCounter = LIMIT;
        skip = BLOCK_BYTES;
        closed = true;
    }

    private void refill() {
        initial[12] = (int) nextCounter++;
        System.arraycopy(initial, 0, work, 0, work.length);
        for (int round = 0; round < 10; round++) {
            quarter(work, 0, 4, 8, 12);
            quarter(work, 1, 5, 9, 13);
            quarter(work, 2, 6, 10, 14);
            quarter(work, 3, 7, 11, 15);
            quarter(work, 0, 5, 10, 15);
            quarter(work, 1, 6, 11, 12);
            quarter(work, 2, 7, 8, 13);
            quarter(work, 3, 4, 9, 14);
        }
        for (int word = 0; word < work.length; word++) {
            WORD.set(stream, 4 * word, work[word] + initial[word]);
        }
        skip = 0;
    }

    private static void quarter(int[] state, int a, int b, int c, int d) {
        int av = state[a];
        int bv = state[b];
        int cv = state[c];
        int dv = state[d];
        av += bv;
        dv = Integer.rotateLeft(dv ^ av, 16);
        cv += dv;
        bv = Integer.rotateLeft(bv ^ cv, 12);
        av += bv;
        dv = Integer.rotateLeft(dv ^ av, 8);
        cv += dv;
        bv = Integer.rotateLeft(bv ^ cv, 7);
        state[a] = av;
        state[b] = bv;
        state[c] = cv;
        state[d] = dv;
    }
}

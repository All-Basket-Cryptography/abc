package org.allbasket.abc.mac.poly1305;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/** RFC 8439 one-time authenticator. Use each key for exactly one message. */
public final class Poly1305 implements AutoCloseable {
    public static final int KEY_BYTES = 32;
    public static final int TAG_BYTES = 16;
    private static final int BLOCK_BYTES = 16;
    private static final int LIMB_BITS = 26;
    private static final long LIMB_MASK = (1L << LIMB_BITS) - 1;
    private static final long WORD_MASK = 0xffffffffL;
    private static final VarHandle WORD =
        MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

    private final long[] r = new long[5];
    private final long[] folded = new long[5];
    private final long[] pad = new long[4];
    private final long[] h = new long[5];
    private final byte[] tail = new byte[BLOCK_BYTES];
    private int used;
    private boolean closed;

    public Poly1305(byte[] oneTimeKey) {
        if (oneTimeKey.length != KEY_BYTES) {
            throw new IllegalArgumentException("Poly1305 requires a 32-byte one-time key");
        }
        r[0] = word(oneTimeKey, 0) & LIMB_MASK;
        r[1] = (word(oneTimeKey, 3) >>> 2) & 0x3ffff03L;
        r[2] = (word(oneTimeKey, 6) >>> 4) & 0x3ffc0ffL;
        r[3] = (word(oneTimeKey, 9) >>> 6) & 0x3f03fffL;
        r[4] = (word(oneTimeKey, 12) >>> 8) & 0x00fffffL;
        for (int i = 1; i < r.length; i++) {
            folded[i] = 5 * r[i];
        }
        for (int i = 0; i < pad.length; i++) {
            pad[i] = word(oneTimeKey, 16 + 4 * i);
        }
    }

    public void update(byte[] message) {
        update(message, 0, message.length);
    }

    /** Absorb the chosen range before returning, with at most 15 bytes retained. */
    public void update(byte[] message, int offset, int length) {
        requireOpen();
        Objects.checkFromIndexSize(offset, length, message.length);
        if (used > 0) {
            int copied = Math.min(BLOCK_BYTES - used, length);
            System.arraycopy(message, offset, tail, used, copied);
            used += copied;
            offset += copied;
            length -= copied;
            if (used < BLOCK_BYTES) {
                return;
            }
            absorb(tail, 0, 1L << 24);
            used = 0;
        }
        while (length >= BLOCK_BYTES) {
            absorb(message, offset, 1L << 24);
            offset += BLOCK_BYTES;
            length -= BLOCK_BYTES;
        }
        System.arraycopy(message, offset, tail, 0, length);
        used = length;
    }

    /** Return the tag in a caller-owned array and close the context. */
    public byte[] finish() {
        requireOpen();
        byte[] tag = new byte[TAG_BYTES];
        if (used > 0) {
            Arrays.fill(tail, used, BLOCK_BYTES, (byte) 0);
            tail[used] = 1;
            absorb(tail, 0, 0);
        }
        carry();
        reduce();

        long f = ((h[0] | h[1] << 26) & WORD_MASK) + pad[0];
        WORD.set(tag, 0, (int) f);
        f = ((h[1] >>> 6 | h[2] << 20) & WORD_MASK) + pad[1] + (f >>> 32);
        WORD.set(tag, 4, (int) f);
        f = ((h[2] >>> 12 | h[3] << 14) & WORD_MASK) + pad[2] + (f >>> 32);
        WORD.set(tag, 8, (int) f);
        f = ((h[3] >>> 18 | h[4] << 8) & WORD_MASK) + pad[3] + (f >>> 32);
        WORD.set(tag, 12, (int) f);
        close();
        return tag;
    }

    public static byte[] authenticate(byte[] oneTimeKey, byte[] message) {
        try (Poly1305 state = new Poly1305(oneTimeKey)) {
            state.update(message);
            return state.finish();
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        Arrays.fill(r, 0);
        Arrays.fill(folded, 0);
        Arrays.fill(pad, 0);
        Arrays.fill(h, 0);
        Arrays.fill(tail, (byte) 0);
        used = 0;
        closed = true;
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Poly1305 context is closed");
        }
    }

    private static long word(byte[] value, int offset) {
        return Integer.toUnsignedLong((int) WORD.get(value, offset));
    }

    private void absorb(byte[] block, int offset, long highBit) {
        long t0 = word(block, offset);
        long t1 = word(block, offset + 4);
        long t2 = word(block, offset + 8);
        long t3 = word(block, offset + 12);
        long h0 = h[0] + (t0 & LIMB_MASK);
        long h1 = h[1] + ((t0 >>> 26 | t1 << 6) & LIMB_MASK);
        long h2 = h[2] + ((t1 >>> 20 | t2 << 12) & LIMB_MASK);
        long h3 = h[3] + ((t2 >>> 14 | t3 << 18) & LIMB_MASK);
        long h4 = h[4] + (t3 >>> 8) + highBit;

        // In radix 2^26 a product of degree five folds back with factor 5.
        h[0] = h0 * r[0] + h1 * folded[4] + h2 * folded[3] + h3 * folded[2] + h4 * folded[1];
        h[1] = h0 * r[1] + h1 * r[0] + h2 * folded[4] + h3 * folded[3] + h4 * folded[2];
        h[2] = h0 * r[2] + h1 * r[1] + h2 * r[0] + h3 * folded[4] + h4 * folded[3];
        h[3] = h0 * r[3] + h1 * r[2] + h2 * r[1] + h3 * r[0] + h4 * folded[4];
        h[4] = h0 * r[4] + h1 * r[3] + h2 * r[2] + h3 * r[1] + h4 * r[0];
        carry();
    }

    private void carry() {
        for (int i = 0; i < h.length - 1; i++) {
            h[i + 1] += h[i] >>> LIMB_BITS;
            h[i] &= LIMB_MASK;
        }
        h[0] += 5 * (h[4] >>> LIMB_BITS);
        h[4] &= LIMB_MASK;
        h[1] += h[0] >>> LIMB_BITS;
        h[0] &= LIMB_MASK;
    }

    private void reduce() {
        long g0 = h[0] + 5;
        long g1 = h[1] + (g0 >>> LIMB_BITS);
        long g2 = h[2] + (g1 >>> LIMB_BITS);
        long g3 = h[3] + (g2 >>> LIMB_BITS);
        long g4 = h[4] + (g3 >>> LIMB_BITS);
        // Overflow of h + 5 selects the residue after subtracting 2^130 - 5.
        long mask = -(g4 >>> LIMB_BITS);
        h[0] = (h[0] & ~mask) | (g0 & LIMB_MASK & mask);
        h[1] = (h[1] & ~mask) | (g1 & LIMB_MASK & mask);
        h[2] = (h[2] & ~mask) | (g2 & LIMB_MASK & mask);
        h[3] = (h[3] & ~mask) | (g3 & LIMB_MASK & mask);
        h[4] = (h[4] & ~mask) | (g4 & LIMB_MASK & mask);
    }
}

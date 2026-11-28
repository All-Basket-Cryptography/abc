package org.allbasket.abc.hash.sha512;

import java.util.Objects;

/** Whole-byte SHA-512 with independent Java compression and reusable streaming state. */
public final class Sha512 {
    public static final int DIGEST_BYTES = 64;

    private static final int BLOCK_BYTES = 128;
    private static final int LENGTH_START = 112;
    private static final long MAX_LENGTH_HIGH = (1L << 61) - 1;
    private static final long[] INITIAL = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
    };
    private static final long[] CONSTANTS = {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
        0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
        0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
        0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
        0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
        0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
        0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
        0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
        0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
        0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
        0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
        0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
        0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
        0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L,
    };

    private final long[] state = INITIAL.clone();
    private final long[] schedule = new long[80];
    private final byte[] buffer = new byte[BLOCK_BYTES];
    private int buffered;
    private long lengthHigh;
    private long lengthLow;

    public static byte[] hash(byte[] input) {
        return new Sha512().update(input).digest();
    }

    public Sha512 update(byte[] input) {
        return update(input, 0, input.length);
    }

    /** Append a validated slice. A rejected range or length preserves the current message. */
    public Sha512 update(byte[] input, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, input.length);
        long nextLow = lengthLow + length;
        lengthHigh = checkedLengthHigh(lengthHigh, lengthLow, nextLow);
        lengthLow = nextLow;

        int cursor = offset;
        int remaining = length;
        if (buffered != 0) {
            int copied = Math.min(remaining, BLOCK_BYTES - buffered);
            System.arraycopy(input, cursor, buffer, buffered, copied);
            buffered += copied;
            if (buffered < BLOCK_BYTES) {
                return this;
            }
            compress(state, buffer, 0);
            cursor += copied;
            remaining -= copied;
        }
        while (remaining >= BLOCK_BYTES) {
            compress(state, input, cursor);
            cursor += BLOCK_BYTES;
            remaining -= BLOCK_BYTES;
        }
        System.arraycopy(input, cursor, buffer, 0, remaining);
        buffered = remaining;
        return this;
    }

    static long checkedLengthHigh(long high, long low, long nextLow) {
        long nextHigh = high + (Long.compareUnsigned(nextLow, low) < 0 ? 1 : 0);
        if (nextHigh > MAX_LENGTH_HIGH) {
            throw new IllegalArgumentException("SHA-512 input exceeds the 128-bit bit-length domain");
        }
        return nextHigh;
    }

    /** Return an owned digest snapshot while leaving the stream open to updates. */
    public byte[] digest() {
        byte[] padded = new byte[buffered < LENGTH_START ? BLOCK_BYTES : 2 * BLOCK_BYTES];
        System.arraycopy(buffer, 0, padded, 0, buffered);
        padded[buffered] = (byte) 0x80;
        writeBitLength(padded, padded.length - 16, lengthHigh, lengthLow);
        long[] finalState = state.clone();
        for (int offset = 0; offset < padded.length; offset += BLOCK_BYTES) {
            compress(finalState, padded, offset);
        }
        byte[] result = new byte[DIGEST_BYTES];
        for (int index = 0; index < finalState.length; index++) {
            writeLong(result, index * 8, finalState[index]);
        }
        return result;
    }

    static void writeBitLength(byte[] output, int offset, long high, long low) {
        writeLong(output, offset, (high << 3) | (low >>> 61));
        writeLong(output, offset + 8, low << 3);
    }

    private static void writeLong(byte[] output, int offset, long word) {
        for (int index = 0; index < 8; index++) {
            output[offset + index] = (byte) (word >>> (56 - 8 * index));
        }
    }

    private static long readLong(byte[] input, int offset) {
        return ((input[offset] & 255L) << 56)
            | ((input[offset + 1] & 255L) << 48)
            | ((input[offset + 2] & 255L) << 40)
            | ((input[offset + 3] & 255L) << 32)
            | ((input[offset + 4] & 255L) << 24)
            | ((input[offset + 5] & 255L) << 16)
            | ((input[offset + 6] & 255L) << 8)
            | (input[offset + 7] & 255L);
    }

    private void compress(long[] chain, byte[] input, int offset) {
        for (int index = 0; index < 16; index++) {
            schedule[index] = readLong(input, offset + 8 * index);
        }
        for (int index = 16; index < schedule.length; index++) {
            long x = schedule[index - 15];
            long y = schedule[index - 2];
            long small0 = Long.rotateRight(x, 1) ^ Long.rotateRight(x, 8) ^ (x >>> 7);
            long small1 = Long.rotateRight(y, 19) ^ Long.rotateRight(y, 61) ^ (y >>> 6);
            schedule[index] = schedule[index - 16] + small0 + schedule[index - 7] + small1;
        }

        long a = chain[0];
        long b = chain[1];
        long c = chain[2];
        long d = chain[3];
        long e = chain[4];
        long f = chain[5];
        long g = chain[6];
        long h = chain[7];
        for (int index = 0; index < schedule.length; index++) {
            long sum1 = Long.rotateRight(e, 14) ^ Long.rotateRight(e, 18) ^ Long.rotateRight(e, 41);
            long choose = (e & f) ^ (~e & g);
            long temp1 = h + sum1 + choose + CONSTANTS[index] + schedule[index];
            long sum0 = Long.rotateRight(a, 28) ^ Long.rotateRight(a, 34) ^ Long.rotateRight(a, 39);
            long majority = (a & b) ^ (a & c) ^ (b & c);
            long temp2 = sum0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        chain[0] += a;
        chain[1] += b;
        chain[2] += c;
        chain[3] += d;
        chain[4] += e;
        chain[5] += f;
        chain[6] += g;
        chain[7] += h;
    }
}

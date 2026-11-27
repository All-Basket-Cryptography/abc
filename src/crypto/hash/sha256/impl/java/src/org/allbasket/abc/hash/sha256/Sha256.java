package org.allbasket.abc.hash.sha256;

import java.util.Objects;

/** Portable SHA-256 over whole-byte inputs, with a reusable streaming state. */
public final class Sha256 {
    public static final int DIGEST_BYTES = 32;
    public static final long MAX_MESSAGE_BYTES = (1L << 61) - 1L;

    private static final int BLOCK_BYTES = 64;
    private static final int[] INITIAL_STATE = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    private static final int[] ROUND_CONSTANTS = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    private final int[] state = INITIAL_STATE.clone();
    private final int[] schedule = new int[64];
    private final byte[] buffer = new byte[BLOCK_BYTES];
    private int buffered;
    private long totalBytes;

    public static byte[] hash(byte[] input) {
        return new Sha256().update(input).digest();
    }

    public Sha256 update(byte[] input) {
        return update(input, 0, input.length);
    }

    /** Append a slice. An invalid range or excessive total leaves the state unchanged. */
    public Sha256 update(byte[] input, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, input.length);
        totalBytes = checkedLength(totalBytes, length);
        int remaining = length;

        if (buffered != 0) {
            int copied = Math.min(remaining, BLOCK_BYTES - buffered);
            System.arraycopy(input, offset, buffer, buffered, copied);
            buffered += copied;
            if (buffered < BLOCK_BYTES) {
                return this;
            }
            compress(state, buffer, 0, schedule);
            offset += copied;
            remaining -= copied;
        }
        while (remaining >= BLOCK_BYTES) {
            compress(state, input, offset, schedule);
            offset += BLOCK_BYTES;
            remaining -= BLOCK_BYTES;
        }
        System.arraycopy(input, offset, buffer, 0, remaining);
        buffered = remaining;
        return this;
    }

    static long checkedLength(long previous, int incoming) {
        if (incoming > MAX_MESSAGE_BYTES - previous) {
            throw new IllegalArgumentException("SHA-256 message exceeds the whole-byte length limit");
        }
        return previous + incoming;
    }

    /** Return a snapshot of the digest, leaving the message available for more updates. */
    public byte[] digest() {
        byte[] padded = new byte[buffered < 56 ? BLOCK_BYTES : 2 * BLOCK_BYTES];
        System.arraycopy(buffer, 0, padded, 0, buffered);
        padded[buffered] = (byte) 0x80;
        // The low 64 bits are the big-endian unsigned bit length, even when the long is negative.
        long bitLength = totalBytes << 3;
        for (int i = 0; i < Long.BYTES; i++) {
            padded[padded.length - 1 - i] = (byte) (bitLength >>> (i * 8));
        }

        int[] finalState = state.clone();
        for (int offset = 0; offset < padded.length; offset += BLOCK_BYTES) {
            compress(finalState, padded, offset, schedule);
        }
        byte[] output = new byte[DIGEST_BYTES];
        for (int i = 0; i < finalState.length; i++) {
            int word = finalState[i];
            int offset = i * Integer.BYTES;
            output[offset] = (byte) (word >>> 24);
            output[offset + 1] = (byte) (word >>> 16);
            output[offset + 2] = (byte) (word >>> 8);
            output[offset + 3] = (byte) word;
        }
        return output;
    }

    private static int loadWord(byte[] input, int offset) {
        return ((input[offset] & 0xff) << 24)
            | ((input[offset + 1] & 0xff) << 16)
            | ((input[offset + 2] & 0xff) << 8)
            | (input[offset + 3] & 0xff);
    }

    private static void compress(int[] state, byte[] input, int offset, int[] schedule) {
        for (int i = 0; i < 16; i++) {
            schedule[i] = loadWord(input, offset + i * Integer.BYTES);
        }
        for (int i = 16; i < 64; i++) {
            int x = schedule[i - 15];
            int y = schedule[i - 2];
            int sigma0 = Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18) ^ (x >>> 3);
            int sigma1 = Integer.rotateRight(y, 17) ^ Integer.rotateRight(y, 19) ^ (y >>> 10);
            schedule[i] = schedule[i - 16] + sigma0 + schedule[i - 7] + sigma1;
        }

        int a = state[0], b = state[1], c = state[2], d = state[3];
        int e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; i++) {
            int sum1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
            int choose = (e & f) ^ (~e & g);
            int t1 = h + sum1 + choose + ROUND_CONSTANTS[i] + schedule[i];
            int sum0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
            int majority = (a & b) ^ (a & c) ^ (b & c);
            int t2 = sum0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
}

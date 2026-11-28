package org.allbasket.abc.hash.sha3256;

import org.allbasket.abc.hash.keccakp1600.KeccakSponge;

/** Byte-oriented SHA3-256 with a non-destructive digest snapshot. */
public final class Sha3_256 {
    private final KeccakSponge sponge = new KeccakSponge();

    public void update(byte[] input) {
        update(input, 0, input.length);
    }

    public void update(byte[] input, int offset, int length) {
        sponge.update(input, offset, length);
    }

    public void reset() {
        sponge.reset();
    }

    public byte[] digest() {
        return sponge.sha3Digest();
    }

    public static byte[] hash(byte[] input) {
        Sha3_256 hasher = new Sha3_256();
        hasher.update(input);
        return hasher.digest();
    }
}

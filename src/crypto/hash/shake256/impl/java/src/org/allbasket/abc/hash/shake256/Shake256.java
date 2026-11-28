package org.allbasket.abc.hash.shake256;

import org.allbasket.abc.hash.keccakp1600.KeccakSponge;

/** Byte-oriented SHAKE256 with independent output readers. */
public final class Shake256 {
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

    public KeccakSponge.Reader finish() {
        return sponge.shakeReader();
    }

    public static byte[] hash(byte[] input, int outputLength) {
        Shake256 absorber = new Shake256();
        absorber.update(input);
        return absorber.finish().read(outputLength);
    }
}

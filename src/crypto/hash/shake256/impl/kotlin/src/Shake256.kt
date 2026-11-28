package org.allbasket.abc.hash.shake256.kotlin

import org.allbasket.abc.hash.keccakp1600.kotlin.KeccakSponge

/** Byte-oriented SHAKE256 with independent output readers. */
class Shake256 {
    private val sponge = KeccakSponge()

    fun update(input: ByteArray) = update(input, 0, input.size)

    fun update(input: ByteArray, offset: Int, length: Int) {
        sponge.update(input, offset, length)
    }

    fun reset() = sponge.reset()

    fun finish(): KeccakSponge.Reader = sponge.shakeReader()

    companion object {
        fun hash(input: ByteArray, outputLength: Int): ByteArray =
            Shake256().apply { update(input) }.finish().read(outputLength)
    }
}

package org.allbasket.abc.hash.sha3256.kotlin

import org.allbasket.abc.hash.keccakp1600.kotlin.KeccakSponge

/** Byte-oriented SHA3-256 with a non-destructive digest snapshot. */
class Sha3_256 {
    private val sponge = KeccakSponge()

    fun update(input: ByteArray) = update(input, 0, input.size)

    fun update(input: ByteArray, offset: Int, length: Int) {
        sponge.update(input, offset, length)
    }

    fun reset() = sponge.reset()

    fun digest(): ByteArray = sponge.sha3Digest()

    companion object {
        fun hash(input: ByteArray): ByteArray = Sha3_256().apply { update(input) }.digest()
    }
}

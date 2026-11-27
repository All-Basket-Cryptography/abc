package org.allbasket.abc.hash.keccakp1600.kotlin

import java.lang.Long.rotateLeft
import java.util.Objects.checkFromIndexSize

/** Keccak-p[1600,24] with a 136-byte byte-oriented rate. */
class KeccakSponge {
    private val lanes = LongArray(25)
    private val pending = ByteArray(RATE_BYTES)
    private var used = 0

    fun reset() {
        lanes.fill(0)
        pending.fill(0)
        used = 0
    }

    fun update(input: ByteArray, offset: Int, length: Int) {
        checkFromIndexSize(offset, length, input.size)
        val end = offset + length
        var cursor = offset
        if (used != 0) {
            val count = minOf(end - cursor, RATE_BYTES - used)
            input.copyInto(pending, used, cursor, cursor + count)
            used += count
            cursor += count
            if (used < RATE_BYTES) return
            absorb(lanes, pending, 0)
        }
        while (end - cursor >= RATE_BYTES) {
            absorb(lanes, input, cursor)
            cursor += RATE_BYTES
        }
        used = end - cursor
        input.copyInto(pending, 0, cursor, end)
    }

    fun sha3Digest(): ByteArray = ByteArray(32).also { encode(finish(0x06), it) }

    fun shakeReader(): Reader = Reader(finish(0x1f))

    private fun finish(suffix: Int): LongArray {
        val block = pending.copyOf()
        block.fill(0, used)
        block[used] = suffix.toByte()
        block[block.lastIndex] = (block.last().toInt() or 0x80).toByte()
        return lanes.copyOf().also { absorb(it, block, 0) }
    }

    class Reader internal constructor(private val lanes: LongArray) {
        private val block = ByteArray(RATE_BYTES).also { encode(lanes, it) }
        private var offset = 0

        fun read(length: Int): ByteArray {
            require(length >= 0) { "SHAKE length must be nonnegative" }
            return ByteArray(length).also { readInto(it, 0, length) }
        }

        fun readInto(output: ByteArray, start: Int, length: Int) {
            checkFromIndexSize(start, length, output.size)
            var cursor = start
            val end = start + length
            while (cursor < end) {
                if (offset == RATE_BYTES) {
                    permute(lanes)
                    encode(lanes, block)
                    offset = 0
                }
                val count = minOf(end - cursor, RATE_BYTES - offset)
                block.copyInto(output, cursor, offset, offset + count)
                offset += count
                cursor += count
            }
        }
    }

    companion object {
        const val RATE_BYTES = 136
        private val rotation = intArrayOf(
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
            41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
        )
        private val pi = intArrayOf(
            0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
            23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
        )
        private val iota = longArrayOf(
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808auL.toLong(), 0x8000000080008000uL.toLong(),
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081uL.toLong(), 0x8000000000008009uL.toLong(),
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008buL.toLong(), 0x8000000000008089uL.toLong(), 0x8000000000008003uL.toLong(),
        0x8000000000008002uL.toLong(), 0x8000000000000080uL.toLong(), 0x000000000000800aL, 0x800000008000000auL.toLong(),
        0x8000000080008081uL.toLong(), 0x8000000000008080uL.toLong(), 0x0000000080000001L, 0x8000000080008008uL.toLong(),
        )

        private fun absorb(state: LongArray, block: ByteArray, offset: Int) {
            for (lane in 0 until RATE_BYTES / 8) {
                var word = 0L
                for (byte in 0..7) {
                    val value = block[offset + 8 * lane + byte].toLong() and 255
                    word = word or (value shl (8 * byte))
                }
                state[lane] = state[lane] xor word
            }
            permute(state)
        }

        private fun encode(state: LongArray, block: ByteArray) {
            for (offset in block.indices) {
                block[offset] = (state[offset / 8] ushr (8 * (offset % 8))).toByte()
            }
        }

        fun permute(state: LongArray) {
            require(state.size == 25) { "Keccak-p[1600] requires 25 lanes" }
            val parity = LongArray(5)
            val theta = LongArray(5)
            val shuffled = LongArray(25)
            for (constant in iota) {
                for (x in 0..4) {
                    parity[x] = state[x] xor state[x + 5] xor state[x + 10] xor state[x + 15] xor state[x + 20]
                }
                for (x in 0..4) {
                    theta[x] = parity[(x + 4) % 5] xor rotateLeft(parity[(x + 1) % 5], 1)
                }
                for (source in state.indices) {
                    shuffled[pi[source]] = rotateLeft(state[source] xor theta[source % 5], rotation[source])
                }
                for (row in 0 until 25 step 5) {
                    val a = shuffled[row]
                    val b = shuffled[row + 1]
                    val c = shuffled[row + 2]
                    val d = shuffled[row + 3]
                    val e = shuffled[row + 4]
                    state[row] = a xor (b.inv() and c)
                    state[row + 1] = b xor (c.inv() and d)
                    state[row + 2] = c xor (d.inv() and e)
                    state[row + 3] = d xor (e.inv() and a)
                    state[row + 4] = e xor (a.inv() and b)
                }
                state[0] = state[0] xor constant
            }
        }
    }
}

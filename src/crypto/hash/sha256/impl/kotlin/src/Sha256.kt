package org.allbasket.abc.hash.sha256.kotlin

/** Whole-byte SHA-256 with independent Kotlin compression and reusable streaming state. */
class Sha256 {
    companion object {
        const val DIGEST_BYTES = 32
        const val MAX_MESSAGE_BYTES = (1L shl 61) - 1
        private const val BLOCK_BYTES = 64
        private val initial = intArrayOf(
            0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
            0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19,
        )
        private val constants = intArrayOf(
            0x428a2f98, 0x71374491, 0xb5c0fbcf.toInt(), 0xe9b5dba5.toInt(),
            0x3956c25b, 0x59f111f1, 0x923f82a4.toInt(), 0xab1c5ed5.toInt(),
            0xd807aa98.toInt(), 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe.toInt(), 0x9bdc06a7.toInt(), 0xc19bf174.toInt(),
            0xe49b69c1.toInt(), 0xefbe4786.toInt(), 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152.toInt(), 0xa831c66d.toInt(), 0xb00327c8.toInt(), 0xbf597fc7.toInt(),
            0xc6e00bf3.toInt(), 0xd5a79147.toInt(), 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e.toInt(), 0x92722c85.toInt(),
            0xa2bfe8a1.toInt(), 0xa81a664b.toInt(), 0xc24b8b70.toInt(), 0xc76c51a3.toInt(),
            0xd192e819.toInt(), 0xd6990624.toInt(), 0xf40e3585.toInt(), 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814.toInt(), 0x8cc70208.toInt(),
            0x90befffa.toInt(), 0xa4506ceb.toInt(), 0xbef9a3f7.toInt(), 0xc67178f2.toInt(),
        )

        fun hash(input: ByteArray): ByteArray = Sha256().update(input).digest()

        internal fun checkedLength(previous: Long, added: Int): Long {
            require(added <= MAX_MESSAGE_BYTES - previous) { "SHA-256 message exceeds the whole-byte length limit" }
            return previous + added
        }
    }

    private val state = initial.copyOf()
    private val schedule = IntArray(64)
    private val buffer = ByteArray(BLOCK_BYTES)
    private var buffered = 0
    private var totalBytes = 0L

    fun update(input: ByteArray): Sha256 = update(input, 0, input.size)

    /** Append only the requested range. A rejected range or length does not change the state. */
    fun update(input: ByteArray, offset: Int, length: Int): Sha256 {
        if (offset < 0 || length < 0 || offset > input.size - length) {
            throw IndexOutOfBoundsException("Invalid SHA-256 input slice")
        }
        totalBytes = checkedLength(totalBytes, length)
        var cursor = offset
        var remaining = length
        if (buffered != 0) {
            val copied = minOf(remaining, BLOCK_BYTES - buffered)
            input.copyInto(buffer, buffered, cursor, cursor + copied)
            buffered += copied
            if (buffered < BLOCK_BYTES) {
                return this
            }
            compress(state, buffer, 0)
            cursor += copied
            remaining -= copied
        }
        while (remaining >= BLOCK_BYTES) {
            compress(state, input, cursor)
            cursor += BLOCK_BYTES
            remaining -= BLOCK_BYTES
        }
        input.copyInto(buffer, 0, cursor, cursor + remaining)
        buffered = remaining
        return this
    }

    /** Return an owned digest snapshot and keep the state available for further updates. */
    fun digest(): ByteArray {
        val padded = ByteArray(if (buffered < 56) BLOCK_BYTES else 2 * BLOCK_BYTES)
        buffer.copyInto(padded, endIndex = buffered)
        padded[buffered] = 0x80.toByte()
        // Interpret the low 64 bits as the unsigned bit length.
        val bits = totalBytes shl 3
        for (i in 0 until 8) {
            padded[padded.lastIndex - i] = (bits ushr (8 * i)).toByte()
        }
        val finalState = state.copyOf()
        for (offset in padded.indices step BLOCK_BYTES) {
            compress(finalState, padded, offset)
        }
        return ByteArray(DIGEST_BYTES) { index ->
            (finalState[index / 4] ushr (24 - (index % 4) * 8)).toByte()
        }
    }

    private fun compress(chain: IntArray, input: ByteArray, offset: Int) {
        for (i in 0 until 16) {
            val p = offset + i * 4
            schedule[i] = ((input[p].toInt() and 0xff) shl 24) or
                ((input[p + 1].toInt() and 0xff) shl 16) or
                ((input[p + 2].toInt() and 0xff) shl 8) or
                (input[p + 3].toInt() and 0xff)
        }
        for (i in 16 until 64) {
            val x = schedule[i - 15]
            val y = schedule[i - 2]
            val sigma0 = x.rotateRight(7) xor x.rotateRight(18) xor (x ushr 3)
            val sigma1 = y.rotateRight(17) xor y.rotateRight(19) xor (y ushr 10)
            schedule[i] = schedule[i - 16] + sigma0 + schedule[i - 7] + sigma1
        }
        var a = chain[0]
        var b = chain[1]
        var c = chain[2]
        var d = chain[3]
        var e = chain[4]
        var f = chain[5]
        var g = chain[6]
        var h = chain[7]
        for (i in 0 until 64) {
            val sum1 = e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)
            val choose = (e and f) xor (e.inv() and g)
            val t1 = h + sum1 + choose + constants[i] + schedule[i]
            val sum0 = a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)
            val majority = (a and b) xor (a and c) xor (b and c)
            val t2 = sum0 + majority
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        }
        chain[0] += a
        chain[1] += b
        chain[2] += c
        chain[3] += d
        chain[4] += e
        chain[5] += f
        chain[6] += g
        chain[7] += h
    }
}

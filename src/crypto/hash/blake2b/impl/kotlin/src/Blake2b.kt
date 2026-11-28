package org.allbasket.abc.hash.blake2b.kotlin

import java.lang.invoke.MethodHandles
import java.nio.ByteOrder

private const val BLOCK_BYTES = 128
private const val MAX_DIGEST_BYTES = 64
private val word = MethodHandles.byteArrayViewVarHandle(LongArray::class.java, ByteOrder.LITTLE_ENDIAN)
private val iv = longArrayOf(
    0x6a09e667f3bcc908uL.toLong(), 0xbb67ae8584caa73buL.toLong(),
    0x3c6ef372fe94f82buL.toLong(), 0xa54ff53a5f1d36f1uL.toLong(),
    0x510e527fade682d1uL.toLong(), 0x9b05688c2b3e6c1fuL.toLong(),
    0x1f83d9abfb41bd6buL.toLong(), 0x5be0cd19137e2179uL.toLong(),
)
private val sigma = arrayOf(
    intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)

/** Sequential unkeyed BLAKE2b. Serialize operations on one instance. */
class Blake2b(val digestSize: Int = MAX_DIGEST_BYTES) {
    init {
        require(digestSize in 1..MAX_DIGEST_BYTES) { "BLAKE2b digest size must be between 1 and 64 bytes" }
    }

    private val state = iv.copyOf()
    private val pending = ByteArray(BLOCK_BYTES)
    private val words = LongArray(16)
    private val v = LongArray(16)
    private var used = 0
    private var compressedLow = 0L
    private var compressedHigh = 0L

    init {
        reset()
    }

    /** Start a fresh stream at the current digest size. */
    fun reset() {
        iv.copyInto(state)
        state[0] = state[0] xor (0x01010000L or digestSize.toLong())
        used = 0
        compressedLow = 0L
        compressedHigh = 0L
    }

    /** Absorb a slice. An invalid range or overflowing byte count leaves the stream unchanged. */
    fun update(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): Blake2b {
        require(offset in 0..input.size && length in 0..input.size - offset) { "Invalid BLAKE2b input range" }
        val totalLow = compressedLow + used.toLong() + length.toLong()
        if (compressedHigh == -1L && java.lang.Long.compareUnsigned(totalLow, compressedLow) < 0) {
            throw ArithmeticException("BLAKE2b message exceeds its 128-bit byte counter")
        }
        val end = offset + length
        val available = BLOCK_BYTES - used
        if (length <= available) {
            input.copyInto(pending, used, offset, end)
            used += length
            return this
        }
        var cursor = offset
        if (used != 0) {
            input.copyInto(pending, used, cursor, cursor + available)
            cursor += available
            consume(pending, 0)
        }
        while (end - cursor > BLOCK_BYTES) {
            consume(input, cursor)
            cursor += BLOCK_BYTES
        }
        input.copyInto(pending, 0, cursor, end)
        used = end - cursor
        return this
    }

    /** Return an owned digest snapshot and leave the stream open for more input. */
    fun digest(): ByteArray {
        val block = ByteArray(BLOCK_BYTES)
        pending.copyInto(block, 0, 0, used)
        val snapshot = state.copyOf()
        val low = compressedLow + used.toLong()
        val carry = if (java.lang.Long.compareUnsigned(low, compressedLow) < 0) 1L else 0L
        compress(snapshot, block, 0, low, compressedHigh + carry, true, LongArray(16), LongArray(16))
        return ByteArray(digestSize) { i -> (snapshot[i / 8] ushr (8 * (i % 8))).toByte() }
    }

    private fun consume(block: ByteArray, offset: Int) {
        compressedLow += BLOCK_BYTES.toLong()
        if (java.lang.Long.compareUnsigned(compressedLow, BLOCK_BYTES.toLong()) < 0) compressedHigh++
        compress(state, block, offset, compressedLow, compressedHigh, false, words, v)
    }

    companion object {
        @JvmStatic
        fun hash(input: ByteArray, digestSize: Int = MAX_DIGEST_BYTES): ByteArray =
            Blake2b(digestSize).update(input).digest()
    }
}

private fun compress(
    state: LongArray, input: ByteArray, offset: Int, low: Long, high: Long, final: Boolean,
    words: LongArray, v: LongArray,
) {
    for (i in words.indices) words[i] = word.get(input, offset + 8 * i) as Long
    state.copyInto(v)
    iv.copyInto(v, 8)
    v[12] = v[12] xor low
    v[13] = v[13] xor high
    if (final) v[14] = v[14].inv()
    for (round in 0..<12) {
        val s = sigma[round % 10]
        mix(v, 0, 4, 8, 12, words[s[0]], words[s[1]])
        mix(v, 1, 5, 9, 13, words[s[2]], words[s[3]])
        mix(v, 2, 6, 10, 14, words[s[4]], words[s[5]])
        mix(v, 3, 7, 11, 15, words[s[6]], words[s[7]])
        mix(v, 0, 5, 10, 15, words[s[8]], words[s[9]])
        mix(v, 1, 6, 11, 12, words[s[10]], words[s[11]])
        mix(v, 2, 7, 8, 13, words[s[12]], words[s[13]])
        mix(v, 3, 4, 9, 14, words[s[14]], words[s[15]])
    }
    for (i in state.indices) state[i] = state[i] xor v[i] xor v[i + 8]
}

private fun mix(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
    v[a] += v[b] + x
    v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 32)
    v[c] += v[d]
    v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 24)
    v[a] += v[b] + y
    v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 16)
    v[c] += v[d]
    v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 63)
}

package org.allbasket.abc.hash.sha512.kotlin

private const val BLOCK_SIZE = 128
private const val LENGTH_START = 112
private const val HIGH_LIMIT = 1L shl 61
private val INITIAL = longArrayOf(
    0x6a09e667f3bcc908uL.toLong(), 0xbb67ae8584caa73buL.toLong(), 0x3c6ef372fe94f82buL.toLong(),
    0xa54ff53a5f1d36f1uL.toLong(), 0x510e527fade682d1uL.toLong(), 0x9b05688c2b3e6c1fuL.toLong(),
    0x1f83d9abfb41bd6buL.toLong(), 0x5be0cd19137e2179uL.toLong(),
)
private val ROUND_CONSTANTS = longArrayOf(
    0x428a2f98d728ae22uL.toLong(), 0x7137449123ef65cduL.toLong(), 0xb5c0fbcfec4d3b2fuL.toLong(),
    0xe9b5dba58189dbbcuL.toLong(), 0x3956c25bf348b538uL.toLong(), 0x59f111f1b605d019uL.toLong(),
    0x923f82a4af194f9buL.toLong(), 0xab1c5ed5da6d8118uL.toLong(), 0xd807aa98a3030242uL.toLong(),
    0x12835b0145706fbeuL.toLong(), 0x243185be4ee4b28cuL.toLong(), 0x550c7dc3d5ffb4e2uL.toLong(),
    0x72be5d74f27b896fuL.toLong(), 0x80deb1fe3b1696b1uL.toLong(), 0x9bdc06a725c71235uL.toLong(),
    0xc19bf174cf692694uL.toLong(), 0xe49b69c19ef14ad2uL.toLong(), 0xefbe4786384f25e3uL.toLong(),
    0x0fc19dc68b8cd5b5uL.toLong(), 0x240ca1cc77ac9c65uL.toLong(), 0x2de92c6f592b0275uL.toLong(),
    0x4a7484aa6ea6e483uL.toLong(), 0x5cb0a9dcbd41fbd4uL.toLong(), 0x76f988da831153b5uL.toLong(),
    0x983e5152ee66dfabuL.toLong(), 0xa831c66d2db43210uL.toLong(), 0xb00327c898fb213fuL.toLong(),
    0xbf597fc7beef0ee4uL.toLong(), 0xc6e00bf33da88fc2uL.toLong(), 0xd5a79147930aa725uL.toLong(),
    0x06ca6351e003826fuL.toLong(), 0x142929670a0e6e70uL.toLong(), 0x27b70a8546d22ffcuL.toLong(),
    0x2e1b21385c26c926uL.toLong(), 0x4d2c6dfc5ac42aeduL.toLong(), 0x53380d139d95b3dfuL.toLong(),
    0x650a73548baf63deuL.toLong(), 0x766a0abb3c77b2a8uL.toLong(), 0x81c2c92e47edaee6uL.toLong(),
    0x92722c851482353buL.toLong(), 0xa2bfe8a14cf10364uL.toLong(), 0xa81a664bbc423001uL.toLong(),
    0xc24b8b70d0f89791uL.toLong(), 0xc76c51a30654be30uL.toLong(), 0xd192e819d6ef5218uL.toLong(),
    0xd69906245565a910uL.toLong(), 0xf40e35855771202auL.toLong(), 0x106aa07032bbd1b8uL.toLong(),
    0x19a4c116b8d2d0c8uL.toLong(), 0x1e376c085141ab53uL.toLong(), 0x2748774cdf8eeb99uL.toLong(),
    0x34b0bcb5e19b48a8uL.toLong(), 0x391c0cb3c5c95a63uL.toLong(), 0x4ed8aa4ae3418acbuL.toLong(),
    0x5b9cca4f7763e373uL.toLong(), 0x682e6ff3d6b2b8a3uL.toLong(), 0x748f82ee5defb2fcuL.toLong(),
    0x78a5636f43172f60uL.toLong(), 0x84c87814a1f0ab72uL.toLong(), 0x8cc702081a6439ecuL.toLong(),
    0x90befffa23631e28uL.toLong(), 0xa4506cebde82bde9uL.toLong(), 0xbef9a3f7b2c67915uL.toLong(),
    0xc67178f2e372532buL.toLong(), 0xca273eceea26619cuL.toLong(), 0xd186b8c721c0c207uL.toLong(),
    0xeada7dd6cde0eb1euL.toLong(), 0xf57d4f7fee6ed178uL.toLong(), 0x06f067aa72176fbauL.toLong(),
    0x0a637dc5a2c898a6uL.toLong(), 0x113f9804bef90daeuL.toLong(), 0x1b710b35131c471buL.toLong(),
    0x28db77f523047d84uL.toLong(), 0x32caab7b40c72493uL.toLong(), 0x3c9ebe0a15c9bebcuL.toLong(),
    0x431d67c49c100d4cuL.toLong(), 0x4cc5d4becb3e42b6uL.toLong(), 0x597f299cfc657e2auL.toLong(),
    0x5fcb6fab3ad6faecuL.toLong(), 0x6c44198c4a475817uL.toLong(),
)

/** A FIPS 180-4 SHA-512 stream. Serialize calls on one instance. */
class Sha512 {
    private val state = INITIAL.copyOf()
    private val tail = ByteArray(BLOCK_SIZE)
    private val schedule = LongArray(16)
    private var used = 0
    private var bytesHigh = 0L
    private var bytesLow = 0L

    fun reset() {
        INITIAL.copyInto(state)
        used = 0
        bytesHigh = 0L
        bytesLow = 0L
    }

    /** Add a slice of the input. Range or length rejection preserves the stream. */
    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Sha512 {
        require(offset in 0..data.size && length in 0..data.size - offset) { "Invalid SHA-512 input range" }
        val low = bytesLow + length.toLong()
        val carry = if (java.lang.Long.compareUnsigned(low, bytesLow) < 0) 1L else 0L
        val high = bytesHigh + carry
        require(high < HIGH_LIMIT) { "SHA-512 input exceeds the 128-bit bit-length domain" }
        bytesHigh = high
        bytesLow = low

        var position = offset
        val end = offset + length
        if (used != 0) {
            val copied = minOf(length, BLOCK_SIZE - used)
            data.copyInto(tail, used, offset, offset + copied)
            used += copied
            if (used < BLOCK_SIZE) return this
            compress(state, tail, 0, schedule)
            position += copied
        }
        while (end - position >= BLOCK_SIZE) {
            compress(state, data, position, schedule)
            position += BLOCK_SIZE
        }
        data.copyInto(tail, 0, position, end)
        used = end - position
        return this
    }

    /** Return an owned digest and keep the stream open for more input. */
    fun digest(): ByteArray {
        val working = state.copyOf()
        val trailer = ByteArray(if (used < LENGTH_START) BLOCK_SIZE else 2 * BLOCK_SIZE)
        tail.copyInto(trailer, endIndex = used)
        trailer[used] = 0x80.toByte()
        putLong(trailer, trailer.size - 16, (bytesHigh shl 3) or (bytesLow ushr 61))
        putLong(trailer, trailer.size - 8, bytesLow shl 3)
        val scratch = LongArray(16)
        for (offset in trailer.indices step BLOCK_SIZE) compress(working, trailer, offset, scratch)
        val result = ByteArray(64)
        for (i in working.indices) putLong(result, i * 8, working[i])
        return result
    }

    companion object {
        fun hash(data: ByteArray): ByteArray = Sha512().update(data).digest()
    }
}

private fun putLong(output: ByteArray, offset: Int, word: Long) {
    for (j in 0..7) output[offset + j] = (word ushr (56 - 8 * j)).toByte()
}

private fun compress(state: LongArray, input: ByteArray, offset: Int, schedule: LongArray) {
    for (i in schedule.indices) {
        var word = 0L
        for (j in 0..7) word = (word shl 8) or (input[offset + 8 * i + j].toLong() and 255L)
        schedule[i] = word
    }
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    for (i in ROUND_CONSTANTS.indices) {
        val slot = i and 15
        if (i >= schedule.size) {
            val x = schedule[(i - 15) and 15]
            val y = schedule[(i - 2) and 15]
            val lower0 = x.rotateRight(1) xor x.rotateRight(8) xor (x ushr 7)
            val lower1 = y.rotateRight(19) xor y.rotateRight(61) xor (y ushr 6)
            schedule[slot] += lower0 + schedule[(i - 7) and 15] + lower1
        }
        val upper1 = e.rotateRight(14) xor e.rotateRight(18) xor e.rotateRight(41)
        val choose = g xor (e and (f xor g))
        val first = h + upper1 + choose + ROUND_CONSTANTS[i] + schedule[slot]
        val upper0 = a.rotateRight(28) xor a.rotateRight(34) xor a.rotateRight(39)
        val majority = (a and b) or (c and (a or b))
        val second = upper0 + majority
        h = g
        g = f
        f = e
        e = d + first
        d = c
        c = b
        b = a
        a = first + second
    }
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h
}

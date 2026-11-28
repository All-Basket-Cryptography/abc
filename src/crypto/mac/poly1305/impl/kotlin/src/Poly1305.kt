package org.allbasket.abc.mac.poly1305.kotlin

class Poly1305(key: ByteArray) : AutoCloseable {
    companion object {
        const val KEY_BYTES = 32
        const val TAG_BYTES = 16
        private const val BITS = 26
        private const val MASK = (1L shl BITS) - 1

        fun authenticate(key: ByteArray, input: ByteArray): ByteArray =
            Poly1305(key).use { mac ->
                mac.update(input)
                mac.finish()
            }
    }

    private val residue = LongArray(5)
    private val r = LongArray(5)
    private val fold = LongArray(5)
    private val scratch = LongArray(5)
    private val pad = LongArray(4)
    private val tail = ByteArray(TAG_BYTES)
    private var used = 0
    private var closed = false

    init {
        require(key.size == KEY_BYTES) { "Expected a 32-byte Poly1305 key" }
        val clipped = key.copyOf(TAG_BYTES)
        for (i in 0 until 4) {
            clipped[4 * i + 3] = (clipped[4 * i + 3].toInt() and 15).toByte()
            pad[i] = load(key, TAG_BYTES + 4 * i)
        }
        for (i in 4..12 step 4) clipped[i] = (clipped[i].toInt() and 252).toByte()
        decode(clipped, 0, r)
        clipped.fill(0)
        for (i in 1..4) fold[i] = 5 * r[i]
    }

    fun update(input: ByteArray, start: Int = 0, end: Int = input.size) {
        check(!closed) { "Poly1305 is closed" }
        require(start in 0..end && end <= input.size) { "Invalid Poly1305 input range" }
        var position = start
        if (used != 0) {
            val count = minOf(TAG_BYTES - used, end - position)
            input.copyInto(tail, used, position, position + count)
            used += count
            position += count
            if (used < TAG_BYTES) return
            absorb(tail, 0, 1L shl 24)
        }
        while (end - position >= TAG_BYTES) {
            absorb(input, position, 1L shl 24)
            position += TAG_BYTES
        }
        input.copyInto(tail, 0, position, end)
        used = end - position
    }

    fun finish(): ByteArray {
        check(!closed) { "Poly1305 is closed" }
        if (used != 0) {
            tail.fill(0, used)
            tail[used] = 1
            absorb(tail, 0, 0)
        }
        carry(residue)
        residue.copyInto(scratch)
        scratch[0] += 5
        for (i in 0 until 4) {
            scratch[i + 1] += scratch[i] ushr BITS
            scratch[i] = scratch[i] and MASK
        }
        val select = -(scratch[4] ushr BITS)
        scratch[4] = scratch[4] and MASK
        for (i in 0..4) residue[i] = residue[i] xor ((residue[i] xor scratch[i]) and select)

        val words = longArrayOf(
            residue[0] or (residue[1] shl 26),
            (residue[1] ushr 6) or (residue[2] shl 20),
            (residue[2] ushr 12) or (residue[3] shl 14),
            (residue[3] ushr 18) or (residue[4] shl 8),
        )
        val tag = ByteArray(TAG_BYTES)
        var extra = 0L
        for (i in 0 until 4) {
            val sum = (words[i] and 0xffffffffL) + pad[i] + extra
            for (j in 0 until 4) tag[4 * i + j] = (sum ushr (8 * j)).toByte()
            extra = sum ushr 32
        }
        words.fill(0)
        close()
        return tag
    }

    override fun close() {
        closed = true
        residue.fill(0)
        r.fill(0)
        fold.fill(0)
        scratch.fill(0)
        pad.fill(0)
        tail.fill(0)
        used = 0
    }

    private fun load(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 255) or ((bytes[offset + 1].toLong() and 255) shl 8) or
            ((bytes[offset + 2].toLong() and 255) shl 16) or ((bytes[offset + 3].toLong() and 255) shl 24)

    private fun decode(block: ByteArray, offset: Int, words: LongArray) {
        val t0 = load(block, offset)
        val t1 = load(block, offset + 4)
        val t2 = load(block, offset + 8)
        val t3 = load(block, offset + 12)
        words[0] = t0 and MASK
        words[1] = ((t0 ushr 26) or (t1 shl 6)) and MASK
        words[2] = ((t1 ushr 20) or (t2 shl 12)) and MASK
        words[3] = ((t2 ushr 14) or (t3 shl 18)) and MASK
        words[4] = t3 ushr 8
    }

    private fun absorb(block: ByteArray, offset: Int, marker: Long) {
        val h = scratch
        decode(block, offset, h)
        for (i in 0..4) h[i] += residue[i]
        h[4] += marker
        // Fold product terms using (2^26)^5 = 5 modulo the Poly1305 prime.
        residue[0] = h[0]*r[0] + h[1]*fold[4] + h[2]*fold[3] + h[3]*fold[2] + h[4]*fold[1]
        residue[1] = h[0]*r[1] + h[1]*r[0] + h[2]*fold[4] + h[3]*fold[3] + h[4]*fold[2]
        residue[2] = h[0]*r[2] + h[1]*r[1] + h[2]*r[0] + h[3]*fold[4] + h[4]*fold[3]
        residue[3] = h[0]*r[3] + h[1]*r[2] + h[2]*r[1] + h[3]*r[0] + h[4]*fold[4]
        residue[4] = h[0]*r[4] + h[1]*r[3] + h[2]*r[2] + h[3]*r[1] + h[4]*r[0]
        carry(residue)
    }

    private fun carry(h: LongArray) {
        for (i in 0 until 4) {
            h[i + 1] += h[i] ushr BITS
            h[i] = h[i] and MASK
        }
        h[0] += (h[4] ushr BITS) * 5
        h[4] = h[4] and MASK
        h[1] += h[0] ushr BITS
        h[0] = h[0] and MASK
    }
}

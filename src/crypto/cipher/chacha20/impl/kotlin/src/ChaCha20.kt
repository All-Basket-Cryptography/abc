package org.allbasket.abc.cipher.chacha20.kotlin

object ChaCha20 {
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 12
    const val BLOCK_BYTES = 64

    fun fitsCounter(size: Long, counter: UInt): Boolean =
        size >= 0 && size <= ((1L shl 32) - counter.toLong()) * BLOCK_BYTES

    fun block(key: ByteArray, nonce: ByteArray, counter: UInt): ByteArray {
        val initial = initialize(key, nonce, counter)
        val work = IntArray(16)
        return try {
            ByteArray(BLOCK_BYTES).also { compress(initial, work, it) }
        } finally {
            initial.fill(0)
            work.fill(0)
        }
    }

    fun xor(key: ByteArray, nonce: ByteArray, counter: UInt, input: ByteArray): ByteArray =
        ByteArray(input.size).also { xorInto(key, nonce, counter, input, it) }

    fun xorInto(key: ByteArray, nonce: ByteArray, counter: UInt, input: ByteArray, output: ByteArray) {
        require(fitsCounter(input.size.toLong(), counter)) { "ChaCha20 counter would wrap" }
        require(output.size >= input.size) { "ChaCha20 destination is too short" }
        val initial = initialize(key, nonce, counter)
        val work = IntArray(16)
        val stream = ByteArray(BLOCK_BYTES)
        try {
            var offset = 0
            while (offset < input.size) {
                initial[12] = counter.toInt() + offset / BLOCK_BYTES
                compress(initial, work, stream)
                val count = minOf(BLOCK_BYTES, input.size - offset)
                for (i in 0 until count) {
                    output[offset + i] = (input[offset + i].toInt() xor stream[i].toInt()).toByte()
                }
                offset += count
            }
        } finally {
            initial.fill(0)
            work.fill(0)
            stream.fill(0)
        }
    }

    private fun load(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 255) or ((bytes[offset + 1].toInt() and 255) shl 8) or
            ((bytes[offset + 2].toInt() and 255) shl 16) or (bytes[offset + 3].toInt() shl 24)

    private fun initialize(key: ByteArray, nonce: ByteArray, counter: UInt): IntArray {
        require(key.size == KEY_BYTES && nonce.size == NONCE_BYTES) { "Expected a 32-byte key and a 12-byte nonce" }
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = load(key, 4 * i)
        state[12] = counter.toInt()
        for (i in 0 until 3) state[13 + i] = load(nonce, 4 * i)
        return state
    }

    private fun quarter(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] += s[b]
        s[d] = Integer.rotateLeft(s[d] xor s[a], 16)
        s[c] += s[d]
        s[b] = Integer.rotateLeft(s[b] xor s[c], 12)
        s[a] += s[b]
        s[d] = Integer.rotateLeft(s[d] xor s[a], 8)
        s[c] += s[d]
        s[b] = Integer.rotateLeft(s[b] xor s[c], 7)
    }

    private fun compress(initial: IntArray, work: IntArray, output: ByteArray) {
        initial.copyInto(work)
        repeat(10) {
            quarter(work, 0, 4, 8, 12)
            quarter(work, 1, 5, 9, 13)
            quarter(work, 2, 6, 10, 14)
            quarter(work, 3, 7, 11, 15)
            quarter(work, 0, 5, 10, 15)
            quarter(work, 1, 6, 11, 12)
            quarter(work, 2, 7, 8, 13)
            quarter(work, 3, 4, 9, 14)
        }
        for (i in work.indices) {
            val word = work[i] + initial[i]
            for (j in 0 until 4) output[4 * i + j] = (word ushr (8 * j)).toByte()
        }
    }
}

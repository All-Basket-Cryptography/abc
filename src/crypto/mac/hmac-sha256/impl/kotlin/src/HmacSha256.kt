package org.allbasket.abc.mac.hmacsha256.kotlin

import org.allbasket.abc.hash.sha256.kotlin.Sha256

/** Streaming RFC 2104 HMAC with the independent Kotlin SHA-256 core. */
class HmacSha256(key: ByteArray) {
    companion object {
        private const val BLOCK_BYTES = 64
        const val TAG_BYTES = Sha256.DIGEST_BYTES
        const val MAX_MESSAGE_BYTES = Sha256.MAX_MESSAGE_BYTES - BLOCK_BYTES

        fun authenticate(key: ByteArray, input: ByteArray): ByteArray = HmacSha256(key).update(input).tag()
    }

    private val inner = Sha256()
    private val outerPad = ByteArray(BLOCK_BYTES) { 0x5c }

    init {
        val normalized = if (key.size > BLOCK_BYTES) Sha256.hash(key) else key
        val innerPad = ByteArray(BLOCK_BYTES) { 0x36 }
        for (index in normalized.indices) {
            val value = normalized[index].toInt()
            innerPad[index] = (value xor 0x36).toByte()
            outerPad[index] = (value xor 0x5c).toByte()
        }
        inner.update(innerPad)
    }

    fun update(input: ByteArray): HmacSha256 = update(input, 0, input.size)

    /** Rejected input leaves the message state unchanged. */
    fun update(input: ByteArray, offset: Int, length: Int): HmacSha256 {
        inner.update(input, offset, length)
        return this
    }

    /** Return an owned tag snapshot and permit later updates. */
    fun tag(): ByteArray = Sha256().update(outerPad).update(inner.digest()).digest()
}

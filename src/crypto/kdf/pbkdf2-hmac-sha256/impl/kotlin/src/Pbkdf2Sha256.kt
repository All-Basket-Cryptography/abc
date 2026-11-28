package org.allbasket.abc.kdf.pbkdf2sha256.kotlin

import org.allbasket.abc.hash.sha256.kotlin.Sha256
import org.allbasket.abc.mac.hmacsha256.kotlin.HmacSha256

/** RFC 8018 PBKDF2 over byte strings using the independent Kotlin HMAC-SHA-256 core. */
object Pbkdf2Sha256 {
    const val MAX_ITERATIONS = 0xffff_ffffL
    private const val TAG_BYTES = HmacSha256.TAG_BYTES

    fun derive(password: ByteArray, salt: ByteArray, iterations: Long, length: Int): ByteArray {
        require(iterations in 1..MAX_ITERATIONS) { "PBKDF2 iteration count is outside 1..$MAX_ITERATIONS" }
        require(length > 0) { "PBKDF2 requires a positive output length" }
        // Normalize long passwords once. JVM array lengths fit the RFC's block index bound.
        val key = if (password.size > 64) Sha256.hash(password) else password
        val output = ByteArray(length)
        for (offset in output.indices step TAG_BYTES) {
            val block = deriveBlock(key, salt, offset / TAG_BYTES + 1, iterations)
            block.copyInto(output, offset, 0, minOf(TAG_BYTES, length - offset))
        }
        return output
    }

    private fun deriveBlock(key: ByteArray, salt: ByteArray, index: Int, iterations: Long): ByteArray {
        val counter = byteArrayOf(
            (index ushr 24).toByte(), (index ushr 16).toByte(), (index ushr 8).toByte(), index.toByte()
        )
        var previous = HmacSha256(key).update(salt).update(counter).tag()
        val accumulated = previous.copyOf()
        for (round in 1 until iterations) {
            previous = HmacSha256.authenticate(key, previous)
            for (position in accumulated.indices) {
                accumulated[position] = (accumulated[position].toInt() xor previous[position].toInt()).toByte()
            }
        }
        return accumulated
    }
}

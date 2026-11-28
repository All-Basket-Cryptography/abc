package org.allbasket.abc.kdf.hkdfsha256.kotlin

import org.allbasket.abc.hash.sha256.kotlin.Sha256
import org.allbasket.abc.mac.hmacsha256.kotlin.HmacSha256

/** RFC 5869 extract and expand using the independent Kotlin HMAC-SHA-256 core. */
object HkdfSha256 {
    const val PRK_BYTES = HmacSha256.TAG_BYTES
    const val MAX_OUTPUT_BYTES = 255 * PRK_BYTES

    /** Return a fresh pseudorandom key. Omitted salt is HashLen zero bytes. */
    fun extract(salt: ByteArray?, inputKeyMaterial: ByteArray): ByteArray =
        HmacSha256.authenticate(salt ?: ByteArray(PRK_BYTES), inputKeyMaterial)

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(prk.size >= PRK_BYTES) { "HKDF PRK must be at least $PRK_BYTES bytes" }
        validateLength(length)
        val key = if (prk.size > 64) Sha256.hash(prk) else prk
        return expandBlocks(key, info, length)
    }

    fun derive(salt: ByteArray?, inputKeyMaterial: ByteArray, info: ByteArray, length: Int): ByteArray {
        validateLength(length)
        return expandBlocks(extract(salt, inputKeyMaterial), info, length)
    }

    private fun validateLength(length: Int) {
        require(length in 0..MAX_OUTPUT_BYTES) { "HKDF output must be between 0 and $MAX_OUTPUT_BYTES bytes" }
    }

    private fun expandBlocks(key: ByteArray, info: ByteArray, length: Int): ByteArray {
        val output = ByteArray(length)
        var previous = ByteArray(0)
        val counter = ByteArray(1)
        for (offset in output.indices step PRK_BYTES) {
            counter[0] = (offset / PRK_BYTES + 1).toByte()
            previous = HmacSha256(key).update(previous).update(info).update(counter).tag()
            previous.copyInto(output, offset, 0, minOf(PRK_BYTES, length - offset))
        }
        return output
    }
}

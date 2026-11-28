package org.allbasket.abc.aead.chacha20poly1305.kotlin

import java.security.MessageDigest
import org.allbasket.abc.cipher.chacha20.kotlin.ChaCha20
import org.allbasket.abc.mac.poly1305.kotlin.Poly1305

object ChaCha20Poly1305 {
    const val KEY_BYTES = ChaCha20.KEY_BYTES
    const val NONCE_BYTES = ChaCha20.NONCE_BYTES
    const val TAG_BYTES = Poly1305.TAG_BYTES
    private val zeros = ByteArray(16)

    data class Sealed(val ciphertext: ByteArray, val tag: ByteArray)

    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): Sealed {
        validate(key, nonce, plaintext.size)
        val stableKey = key.copyOf()
        val stableNonce = nonce.copyOf()
        return try {
            val ciphertext = ChaCha20.xor(stableKey, stableNonce, 1u, plaintext)
            Sealed(ciphertext, authenticate(stableKey, stableNonce, aad, ciphertext))
        } finally {
            stableKey.fill(0)
            stableNonce.fill(0)
        }
    }

    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray? {
        validate(key, nonce, ciphertext.size)
        if (tag.size != TAG_BYTES) return null
        val stableKey = key.copyOf()
        val stableNonce = nonce.copyOf()
        val stableCiphertext = ciphertext.copyOf()
        return try {
            val expected = authenticate(stableKey, stableNonce, aad, stableCiphertext)
            try {
                if (!MessageDigest.isEqual(expected, tag)) null
                else ChaCha20.xor(stableKey, stableNonce, 1u, stableCiphertext)
            } finally {
                expected.fill(0)
            }
        } finally {
            stableKey.fill(0)
            stableNonce.fill(0)
        }
    }

    fun openInto(
        key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray, tag: ByteArray, output: ByteArray,
    ): Boolean {
        require(output.size >= ciphertext.size) { "Plaintext destination is too short" }
        val verified = open(key, nonce, aad, ciphertext, tag) ?: return false
        verified.copyInto(output)
        verified.fill(0)
        return true
    }

    private fun validate(key: ByteArray, nonce: ByteArray, size: Int) {
        require(key.size == KEY_BYTES && nonce.size == NONCE_BYTES) { "Expected a 32-byte key and a 12-byte nonce" }
        require(ChaCha20.fitsCounter(size.toLong(), 1u)) { "ChaCha20-Poly1305 counter would wrap" }
    }

    private fun authenticate(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val block = ChaCha20.block(key, nonce, 0u)
        val oneTime = block.copyOf(Poly1305.KEY_BYTES)
        block.fill(0)
        return try {
            Poly1305(oneTime).use { mac ->
                padded(mac, aad)
                padded(mac, ciphertext)
                val lengths = ByteArray(16)
                littleEndian(lengths, 0, aad.size.toLong())
                littleEndian(lengths, 8, ciphertext.size.toLong())
                mac.update(lengths)
                mac.finish()
            }
        } finally {
            oneTime.fill(0)
        }
    }

    private fun padded(mac: Poly1305, input: ByteArray) {
        mac.update(input)
        mac.update(zeros, end = (16 - input.size % 16) % 16)
    }

    private fun littleEndian(output: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) output[offset + i] = (value ushr (8 * i)).toByte()
    }
}

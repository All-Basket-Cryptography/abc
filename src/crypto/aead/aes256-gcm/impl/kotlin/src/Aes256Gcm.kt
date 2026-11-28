package org.allbasket.abc.aead.aes256gcm.kotlin

import java.security.GeneralSecurityException
import java.security.NoSuchProviderException
import java.security.Provider
import java.security.Security
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** AES-256-GCM with fixed 96-bit nonces and detached 128-bit tags. */
class Aes256Gcm @Throws(NoSuchProviderException::class) constructor(key: ByteArray) {
    companion object {
        const val KEY_BYTES = 32
        const val NONCE_BYTES = 12
        const val TAG_BYTES = 16
        const val MAX_PAYLOAD_BYTES = ((1L shl 32) - 2) * 16
        const val MAX_ARRAY_PAYLOAD_BYTES = Int.MAX_VALUE - TAG_BYTES
    }

    private val ownedKey: SecretKeySpec
    private val provider: Provider

    init {
        require(key.size == KEY_BYTES) { "AES-256-GCM requires a 32-byte key" }
        val candidate = Security.getProvider("SunJCE")
        if (candidate == null || candidate.javaClass.module !== Any::class.java.module ||
            candidate.javaClass.name != "com.sun.crypto.provider.SunJCE"
        ) {
            throw NoSuchProviderException("The built-in SunJCE provider is required")
        }
        provider = candidate
        ownedKey = SecretKeySpec(key, "AES")
    }

    /** The returned arrays belong to the caller. */
    class Sealed(private val ciphertext: ByteArray, private val tag: ByteArray) {
        fun ciphertext(): ByteArray = ciphertext
        fun tag(): ByteArray = tag
    }

    @Throws(GeneralSecurityException::class)
    fun seal(nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): Sealed {
        validate(nonce, plaintext.size)
        val cipher = initialize(Cipher.ENCRYPT_MODE, nonce, aad)
        val combined = cipher.doFinal(plaintext)
        return Sealed(combined.copyOf(plaintext.size), combined.copyOfRange(plaintext.size, combined.size))
    }

    @Throws(GeneralSecurityException::class)
    fun open(nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray? {
        validate(nonce, ciphertext.size)
        if (tag.size != TAG_BYTES) {
            return null
        }
        val combined = ciphertext.copyOf(ciphertext.size + TAG_BYTES)
        tag.copyInto(combined, ciphertext.size)
        val cipher = initialize(Cipher.DECRYPT_MODE, nonce, aad)
        return try {
            cipher.doFinal(combined)
        } catch (_: AEADBadTagException) {
            null
        }
    }

    private fun validate(nonce: ByteArray, bytes: Int) {
        require(nonce.size == NONCE_BYTES) { "AES-256-GCM requires a 12-byte nonce" }
        require(bytes <= MAX_ARRAY_PAYLOAD_BYTES) {
            "AES-256-GCM payload and tag exceed the byte-array representation"
        }
    }

    private fun initialize(mode: Int, nonce: ByteArray, aad: ByteArray): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
        cipher.init(mode, ownedKey, GCMParameterSpec(8 * TAG_BYTES, nonce))
        cipher.updateAAD(aad)
        return cipher
    }
}

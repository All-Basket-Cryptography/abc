package org.allbasket.abc.cipher.aes256.kotlin

import java.security.GeneralSecurityException
import java.security.NoSuchProviderException
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** Single-block AES-256 with the JVM's built-in SunJCE provider. */
class Aes256 @Throws(GeneralSecurityException::class) constructor(key: ByteArray) {
    companion object {
        const val KEY_BYTES = 32
        const val BLOCK_BYTES = 16
        private const val TRANSFORMATION = "AES/ECB/NoPadding"
    }

    private val encrypt: Cipher
    private val decrypt: Cipher

    init {
        require(key.size == KEY_BYTES) { "AES-256 requires a 32-byte key" }
        val provider = Security.getProvider("SunJCE")
        if (provider == null || provider.javaClass.module !== Any::class.java.module ||
            provider.javaClass.name != "com.sun.crypto.provider.SunJCE"
        ) {
            throw NoSuchProviderException("The built-in SunJCE provider is required")
        }
        val ownedKey = SecretKeySpec(key, "AES")
        encrypt = Cipher.getInstance(TRANSFORMATION, provider)
        decrypt = Cipher.getInstance(TRANSFORMATION, provider)
        encrypt.init(Cipher.ENCRYPT_MODE, ownedKey)
        decrypt.init(Cipher.DECRYPT_MODE, ownedKey)
    }

    @Throws(GeneralSecurityException::class)
    fun encryptBlock(block: ByteArray): ByteArray = apply(encrypt, block)

    @Throws(GeneralSecurityException::class)
    fun decryptBlock(block: ByteArray): ByteArray = apply(decrypt, block)

    private fun apply(cipher: Cipher, block: ByteArray): ByteArray {
        require(block.size == BLOCK_BYTES) { "AES-256 accepts exactly one 16-byte block" }
        return cipher.doFinal(block)
    }
}

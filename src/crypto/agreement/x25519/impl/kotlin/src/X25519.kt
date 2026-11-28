package org.allbasket.abc.agreement.x25519.kotlin

import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.NoSuchProviderException
import java.security.Provider
import java.security.Security
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement

/** RFC 7748 raw X25519 with the built-in SunEC provider. */
object X25519 {
    const val KEY_BYTES = 32
    private const val ALGORITHM = "X25519"
    private val field = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun publicKey(privateKey: ByteArray): ByteArray {
        requireWidth(privateKey)
        return agreement(privateKey, BigInteger.valueOf(9))
            ?: throw InvalidKeyException("SunEC rejected the X25519 base point")
    }

    /** Return the 32-byte shared secret, or null for an invalid low-order peer. */
    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun sharedSecret(privateKey: ByteArray, peer: ByteArray): ByteArray? {
        requireWidth(privateKey)
        requireWidth(peer)
        val coordinate = peer.reversedArray()
        coordinate[0] = (coordinate[0].toInt() and 0x7f).toByte()
        return agreement(privateKey, BigInteger(1, coordinate).mod(field))
    }

    private fun requireWidth(key: ByteArray) {
        require(key.size == KEY_BYTES) { "X25519 requires 32-byte keys" }
    }

    private fun builtInProvider(): Provider {
        val provider = Security.getProvider("SunEC")
        val origin = ModuleLayer.boot().findModule("jdk.crypto.ec").orElse(null)
        if (provider == null || provider.javaClass.module !== origin ||
            provider.javaClass.name != "sun.security.ec.SunEC"
        ) {
            throw NoSuchProviderException("The built-in SunEC provider is required")
        }
        return provider
    }

    private fun agreement(privateKey: ByteArray, u: BigInteger): ByteArray? {
        val provider = builtInProvider()
        val factory = KeyFactory.getInstance(ALGORITHM, provider)
        val x25519 = KeyAgreement.getInstance(ALGORITHM, provider)
        x25519.init(factory.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, privateKey)))
        val peerKey = factory.generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, u))
        try {
            x25519.doPhase(peerKey, true)
        } catch (_: InvalidKeyException) {
            return null
        }
        val secret = x25519.generateSecret()
        if (secret.size != KEY_BYTES) {
            throw GeneralSecurityException("SunEC returned an unexpected X25519 output length")
        }
        var nonzero = 0
        for (value in secret) {
            nonzero = nonzero or value.toInt()
        }
        return if (nonzero == 0) null else secret
    }
}

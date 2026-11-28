package org.allbasket.abc.agreement.mlkem768.kotlin

import java.security.SecureRandom
import javax.security.auth.DestroyFailedException
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters

/** Seed-format FIPS 203 ML-KEM-768 via the pinned Bouncy Castle lightweight API. */
object MlKem768 {
    const val SEED_BYTES = 64
    const val PUBLIC_BYTES = 1184
    const val CIPHERTEXT_BYTES = 1088
    const val SECRET_BYTES = 32
    private const val POLYNOMIAL_BYTES = 1152
    private const val MODULUS = 3329
    private val parameters = MLKEMParameters.ml_kem_768
    private val random = SecureRandom()

    /** Returned ciphertext and secret arrays belong to the caller. */
    class Encapsulation(private val ciphertext: ByteArray, private val secret: ByteArray) {
        fun ciphertext(): ByteArray = ciphertext
        fun secret(): ByteArray = secret
    }

    @JvmStatic
    fun generateKey(): DecapsulationKey {
        val seed = ByteArray(SEED_BYTES)
        try {
            random.nextBytes(seed)
            return fromSeed(seed)
        } finally {
            seed.fill(0)
        }
    }

    @JvmStatic
    fun fromSeed(seed: ByteArray): DecapsulationKey {
        require(seed.size == SEED_BYTES) { "ML-KEM-768 requires a 64-byte d || z seed" }
        return DecapsulationKey.fromSeed(seed)
    }

    @JvmStatic
    fun encapsulate(publicKey: ByteArray): Encapsulation {
        require(publicKey.size == PUBLIC_BYTES) { "Incorrect ML-KEM-768 public key length" }
        val encoded = publicKey.copyOf()
        for (i in 0 until POLYNOMIAL_BYTES step 3) {
            val a = encoded[i].toInt() and 255
            val b = encoded[i + 1].toInt() and 255
            val c = encoded[i + 2].toInt() and 255
            require((a or ((b and 15) shl 8)) < MODULUS && ((b ushr 4) or (c shl 4)) < MODULUS) {
                "Noncanonical ML-KEM-768 public key"
            }
        }
        val key = MLKEMPublicKeyParameters(parameters, encoded)
        val encapsulated = MLKEMGenerator(random).generateEncapsulated(key)
        try {
            return Encapsulation(encapsulated.encapsulation, encapsulated.secret)
        } finally {
            try {
                encapsulated.destroy()
            } catch (failure: DestroyFailedException) {
                throw IllegalStateException("Could not clear the provider encapsulation", failure)
            }
        }
    }

    class DecapsulationKey private constructor(private var key: MLKEMPrivateKeyParameters?) : AutoCloseable {
        companion object {
            @JvmSynthetic
            internal fun fromSeed(seed: ByteArray): DecapsulationKey =
                DecapsulationKey(MLKEMPrivateKeyParameters(parameters, seed))
        }

        @Synchronized
        fun publicKey(): ByteArray = requireKey().publicKey

        /** Returns the implicit-rejection secret for a correctly sized invalid ciphertext. */
        @Synchronized
        fun decapsulate(ciphertext: ByteArray): ByteArray {
            val current = requireKey()
            require(ciphertext.size == CIPHERTEXT_BYTES) { "Incorrect ML-KEM-768 ciphertext length" }
            return MLKEMExtractor(current).extractSecret(ciphertext)
        }

        @Synchronized
        override fun close() {
            key?.destroy()
            key = null
        }

        private fun requireKey(): MLKEMPrivateKeyParameters =
            checkNotNull(key) { "ML-KEM-768 key is closed" }
    }
}

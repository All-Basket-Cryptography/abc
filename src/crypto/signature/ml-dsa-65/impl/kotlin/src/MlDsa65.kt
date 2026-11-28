package org.allbasket.abc.signature.mldsa65.kotlin

import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithContext
import org.bouncycastle.crypto.signers.MLDSASigner

/** Pure deterministic FIPS 204 ML-DSA-65 with binary context and raw encodings. */
object MlDsa65 {
    const val SEED_BYTES = 32
    const val PUBLIC_BYTES = 1952
    const val SIGNATURE_BYTES = 3309
    const val MAX_CONTEXT_BYTES = 255
    private const val MAX_HINTS = 55
    private const val HINT_POLYNOMIALS = 6
    private const val HINT_OFFSET = SIGNATURE_BYTES - MAX_HINTS - HINT_POLYNOMIALS
    private val parameters = MLDSAParameters.ml_dsa_65

    @JvmStatic
    fun publicKey(seed: ByteArray): ByteArray {
        val key = importSeed(seed)
        try {
            return key.publicKey
        } finally {
            key.destroy()
        }
    }

    @JvmStatic
    @Throws(CryptoException::class)
    fun sign(seed: ByteArray, message: ByteArray, context: ByteArray): ByteArray {
        require(context.size <= MAX_CONTEXT_BYTES) { "ML-DSA-65 context exceeds 255 bytes" }
        val key = importSeed(seed)
        try {
            val signer = MLDSASigner()
            signer.init(true, ParametersWithContext(key, context))
            signer.update(message, 0, message.size)
            return signer.generateSignature()
        } finally {
            key.destroy()
        }
    }

    @JvmStatic
    fun verify(publicKey: ByteArray, message: ByteArray, context: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != PUBLIC_BYTES || context.size > MAX_CONTEXT_BYTES ||
            signature.size != SIGNATURE_BYTES) {
            return false
        }
        val encoded = signature.copyOf()
        if (!canonicalHints(encoded)) {
            return false
        }
        val key = MLDSAPublicKeyParameters(parameters, publicKey)
        val verifier = MLDSASigner()
        verifier.init(false, ParametersWithContext(key, context))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(encoded)
    }

    private fun importSeed(seed: ByteArray): MLDSAPrivateKeyParameters {
        require(seed.size == SEED_BYTES) { "ML-DSA-65 requires a 32-byte seed" }
        // The pinned provider retains the supplied seed array and clears it on destroy.
        val owned = seed.copyOf()
        try {
            return MLDSAPrivateKeyParameters(parameters, owned)
        } catch (failure: Throwable) {
            owned.fill(0)
            throw failure
        }
    }

    private fun canonicalHints(signature: ByteArray): Boolean {
        var start = 0
        for (i in 0 until HINT_POLYNOMIALS) {
            val end = signature[HINT_OFFSET + MAX_HINTS + i].toInt() and 255
            if (end < start || end > MAX_HINTS) {
                return false
            }
            var previous = -1
            for (j in start until end) {
                val index = signature[HINT_OFFSET + j].toInt() and 255
                if (index <= previous) {
                    return false
                }
                previous = index
            }
            start = end
        }
        for (j in start until MAX_HINTS) {
            if (signature[HINT_OFFSET + j].toInt() != 0) {
                return false
            }
        }
        return true
    }
}

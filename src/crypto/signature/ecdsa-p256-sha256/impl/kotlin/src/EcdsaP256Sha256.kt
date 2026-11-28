package org.allbasket.abc.signature.ecdsap256sha256.kotlin

import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.signers.DSAKCalculator
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import org.bouncycastle.util.BigIntegers

/** RFC 6979 deterministic P-256 ECDSA with SHA-256 and P1363 signatures. */
object EcdsaP256Sha256 {
    const val PRIVATE_KEY_BYTES = 32
    const val PUBLIC_KEY_BYTES = 65
    const val COMPRESSED_KEY_BYTES = 33
    const val SIGNATURE_BYTES = 64
    private val domain = CustomNamedCurves.getByName("secp256r1").let {
        ECDomainParameters(it.curve, it.g, it.n, it.h)
    }

    @JvmStatic
    fun publicKey(scalar: ByteArray): ByteArray =
        FixedPointCombMultiplier().multiply(domain.g, privateScalar(scalar)).getEncoded(false)

    @JvmStatic
    fun sign(scalar: ByteArray, message: ByteArray): ByteArray {
        val key = ECPrivateKeyParameters(privateScalar(scalar), domain)
        val signature = Nonce().use { nonce ->
            val signer = ECDSASigner(nonce)
            signer.init(true, key)
            signer.generateSignature(hash(message))
        }
        val output = ByteArray(SIGNATURE_BYTES)
        for (i in signature.indices) {
            BigIntegers.asUnsignedByteArray(PRIVATE_KEY_BYTES, signature[i]).copyInto(output, i * PRIVATE_KEY_BYTES)
        }
        return output
    }

    private class Nonce : DSAKCalculator, AutoCloseable {
        private val mac = HMac(SHA256Digest())
        private val key = ByteArray(PRIVATE_KEY_BYTES)
        private val value = ByteArray(PRIVATE_KEY_BYTES)
        private lateinit var order: BigInteger
        private var issued = false

        override fun isDeterministic(): Boolean = true

        override fun init(n: BigInteger, random: SecureRandom) {
            throw UnsupportedOperationException("Only deterministic signing is supported")
        }

        override fun init(n: BigInteger, scalar: BigInteger, digest: ByteArray) {
            order = n
            issued = false
            key.fill(0)
            value.fill(1)
            val secret = BigIntegers.asUnsignedByteArray(PRIVATE_KEY_BYTES, scalar)
            val hashed = BigIntegers.asUnsignedByteArray(PRIVATE_KEY_BYTES, BigInteger(1, digest).mod(n))
            try {
                mac.init(KeyParameter(key))
                updateKey(0, secret, hashed)
                updateKey(1, secret, hashed)
            } finally {
                secret.fill(0)
            }
        }

        private fun updateKey(separator: Byte, vararg suffix: ByteArray) {
            mac.update(value, 0, value.size)
            mac.update(separator)
            for (part in suffix) mac.update(part, 0, part.size)
            mac.doFinal(key, 0)
            mac.init(KeyParameter(key))
            advanceValue()
        }

        private fun advanceValue() {
            mac.update(value, 0, value.size)
            mac.doFinal(value, 0)
        }

        override fun nextK(): BigInteger {
            // A repeated request means the signer produced zero r or s.
            // Apply the same RFC 6979 §3.2(h.3) update as for an invalid k.
            if (issued) updateKey(0)
            while (true) {
                advanceValue()
                val candidate = BigInteger(1, value)
                if (candidate.signum() > 0 && candidate < order) {
                    issued = true
                    return candidate
                }
                updateKey(0)
            }
        }

        override fun close() {
            value.fill(0)
            key.fill(0)
            mac.init(KeyParameter(key))
        }
    }

    @JvmStatic
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val compressed = publicKey.size == COMPRESSED_KEY_BYTES && publicKey[0].toInt() in 2..3
        val uncompressed = publicKey.size == PUBLIC_KEY_BYTES && publicKey[0].toInt() == 4
        if ((!compressed && !uncompressed) || signature.size != SIGNATURE_BYTES) {
            return false
        }
        val r = BigInteger(1, signature, 0, PRIVATE_KEY_BYTES)
        val s = BigInteger(1, signature, PRIVATE_KEY_BYTES, PRIVATE_KEY_BYTES)
        if (!validScalar(r) || !validScalar(s)) {
            return false
        }
        val key = try {
            val point = domain.curve.decodePoint(publicKey)
            if (!publicKey.contentEquals(point.getEncoded(compressed))) {
                return false
            }
            ECPublicKeyParameters(point, domain)
        } catch (_: IllegalArgumentException) {
            return false
        }
        val verifier = ECDSASigner()
        verifier.init(false, key)
        return verifier.verifySignature(hash(message), r, s)
    }

    private fun privateScalar(scalar: ByteArray): BigInteger {
        require(scalar.size == PRIVATE_KEY_BYTES) { "P-256 private scalar must be 32 bytes" }
        val value = BigInteger(1, scalar)
        require(validScalar(value)) { "P-256 private scalar is outside 1..n-1" }
        return value
    }

    private fun validScalar(value: BigInteger): Boolean = value.signum() > 0 && value < domain.n

    private fun hash(message: ByteArray): ByteArray {
        val digest = SHA256Digest()
        digest.update(message, 0, message.size)
        val output = ByteArray(32)
        digest.doFinal(output, 0)
        return output
    }
}

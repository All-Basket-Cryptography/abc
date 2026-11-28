package org.allbasket.abc.signature.ed25519.kotlin

import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.NoSuchProviderException
import java.security.Provider
import java.security.ProviderException
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.EdECPrivateKey
import java.security.interfaces.EdECPublicKey
import java.security.spec.EdECPoint
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec

/** Pure Ed25519 with seed-only signing and strict point validation. */
object Ed25519 {
    const val SEED_BYTES = 32
    const val PUBLIC_BYTES = 32
    const val SIGNATURE_BYTES = 64
    private const val ALGORITHM = "Ed25519"
    private val parameters = NamedParameterSpec.ED25519
    private val one = BigInteger.ONE
    private val field = one.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val order = one.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
    private val d = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(field)).mod(field)
    private val sqrtExponent = field.subtract(BigInteger.valueOf(5)).shiftRight(3)
    private val sqrtMinusOne = BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752")

    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun publicKey(seed: ByteArray): ByteArray {
        requireSeed(seed)
        val random = SeedInput(seed)
        try {
            val generator = KeyPairGenerator.getInstance(ALGORITHM, builtInProvider())
            generator.initialize(parameters, random)
            val pair = generator.generateKeyPair()
            val privateKey = pair.private as? EdECPrivateKey
            val publicKey = pair.public as? EdECPublicKey
            if (privateKey == null || publicKey == null || !random.used) {
                throw GeneralSecurityException("Unexpected SunEC seed derivation")
            }
            val derived = privateKey.bytes.orElseThrow {
                GeneralSecurityException("SunEC did not return its derived seed")
            }
            try {
                if (!MessageDigest.isEqual(derived, random.seed)) {
                    throw GeneralSecurityException("SunEC did not use the supplied Ed25519 seed")
                }
            } finally {
                derived.fill(0)
            }
            return encode(publicKey.point)
        } finally {
            random.seed.fill(0)
        }
    }

    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        requireSeed(seed)
        val provider = builtInProvider()
        val factory = KeyFactory.getInstance(ALGORITHM, provider)
        val signer = Signature.getInstance(ALGORITHM, provider)
        signer.initSign(factory.generatePrivate(EdECPrivateKeySpec(parameters, seed)))
        signer.update(message)
        return signer.sign()
    }

    /** Check canonical A, R and S, reject small-order A and R, then verify. */
    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun verifyStrict(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != PUBLIC_BYTES || signature.size != SIGNATURE_BYTES) {
            return false
        }
        val wire = signature.copyOf()
        val point = decode(publicKey) ?: return false
        if (scalar(wire, PUBLIC_BYTES, false) >= order || decode(wire) == null) {
            return false
        }
        val provider = builtInProvider()
        val factory = KeyFactory.getInstance(ALGORITHM, provider)
        val verifier = Signature.getInstance(ALGORITHM, provider)
        return try {
            verifier.initVerify(factory.generatePublic(EdECPublicKeySpec(parameters, point)))
            verifier.update(message)
            verifier.verify(wire)
        } catch (_: InvalidKeyException) {
            false
        } catch (_: SignatureException) {
            false
        }
    }

    private fun decode(wire: ByteArray): EdECPoint? {
        val encoded = wire.copyOf(PUBLIC_BYTES)
        val odd = (encoded[PUBLIC_BYTES - 1].toInt() and 128) != 0
        val y = scalar(encoded, 0, true)
        if (y >= field) {
            return null
        }
        val y2 = mul(y, y)
        val u = y2.subtract(one).mod(field)
        val v = mul(d, y2).add(one).mod(field)
        val v3 = mul(mul(v, v), v)
        val v7 = mul(mul(v3, v3), v)
        var x = mul(mul(u, v3), mul(u, v7).modPow(sqrtExponent, field))
        val check = mul(v, mul(x, x))
        if (check != u) {
            if (check.add(u).mod(field).signum() != 0) {
                return null
            }
            x = mul(x, sqrtMinusOne)
        }
        if ((odd && x.signum() == 0) || smallOrder(x, y)) {
            return null
        }
        return EdECPoint(odd, y)
    }

    private fun smallOrder(x: BigInteger, y: BigInteger): Boolean {
        // Either square root of x² gives the same cofactor identity result.
        var point = Point(x, y, one, mul(x, y))
        repeat(3) {
            point = point.twice()
        }
        return point.x.signum() == 0 && point.y == point.z
    }

    private class Point(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger) {
        fun twice(): Point {
            val minus = y.subtract(x)
            val plus = y.add(x)
            val a = mul(minus, minus)
            val b = mul(plus, plus)
            val c = mul(d, mul(t, t)).shiftLeft(1)
            val d2 = mul(z, z).shiftLeft(1)
            val e = b.subtract(a)
            val f = d2.subtract(c)
            val g = d2.add(c)
            val h = b.add(a)
            return Point(mul(e, f), mul(g, h), mul(f, g), mul(e, h))
        }
    }

    private fun mul(a: BigInteger, b: BigInteger): BigInteger = a.multiply(b).mod(field)

    private fun scalar(source: ByteArray, offset: Int, clearHighBit: Boolean): BigInteger {
        val reversed = ByteArray(PUBLIC_BYTES) { i -> source[offset + PUBLIC_BYTES - 1 - i] }
        if (clearHighBit) {
            reversed[0] = (reversed[0].toInt() and 0x7f).toByte()
        }
        return BigInteger(1, reversed)
    }

    private fun encode(point: EdECPoint): ByteArray {
        val bigEndian = point.y.toByteArray()
        val result = ByteArray(PUBLIC_BYTES)
        for (i in bigEndian.indices) {
            result[i] = bigEndian[bigEndian.size - 1 - i]
        }
        if (point.isXOdd) {
            result[PUBLIC_BYTES - 1] = (result[PUBLIC_BYTES - 1].toInt() or 128).toByte()
        }
        return result
    }

    private fun requireSeed(seed: ByteArray) {
        require(seed.size == SEED_BYTES) { "Ed25519 requires a 32-byte seed" }
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

    private class SeedInput(seed: ByteArray) : SecureRandom() {
        val seed = seed.copyOf()
        var used = false
            private set

        override fun nextBytes(target: ByteArray) {
            if (used || target.size != SEED_BYTES) {
                throw ProviderException("Unexpected SunEC Ed25519 seed request")
            }
            seed.copyInto(target)
            used = true
        }

        override fun generateSeed(bytes: Int): ByteArray {
            throw ProviderException("Unexpected SunEC Ed25519 entropy request")
        }
    }
}

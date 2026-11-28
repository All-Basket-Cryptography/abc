package org.allbasket.abc.kdf.hkdfsha256.kotlin

import java.util.HexFormat
import java.util.Random
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private val hex = HexFormat.of()

private fun referenceMac(key: ByteArray?): Mac =
    Mac.getInstance("HmacSHA256", "SunJCE").apply {
        // JCA rejects an empty byte-array key; its padded form is all zeroes.
        init(SecretKeySpec(if (key == null || key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
    }

private fun referenceExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
    val mac = referenceMac(prk)
    val output = ByteArray(length)
    var previous = ByteArray(0)
    var written = 0
    var index = 1
    while (written < length) {
        mac.update(previous)
        mac.update(info)
        mac.update(index.toByte())
        previous = mac.doFinal()
        val count = minOf(previous.size, length - written)
        previous.copyInto(output, written, 0, count)
        written += count
        index++
    }
    return output
}

private fun checkDerivation(salt: ByteArray?, ikm: ByteArray, info: ByteArray,
                            expectedPrk: ByteArray, expected: ByteArray) {
    val prk = HkdfSha256.extract(salt, ikm)
    check(prk.contentEquals(expectedPrk)) { "extract mismatch" }
    check(HkdfSha256.expand(prk, info, expected.size).contentEquals(expected)) { "expand mismatch" }
    val result = HkdfSha256.derive(salt, ikm, info, expected.size)
    check(result.contentEquals(expected)) { "derive mismatch" }
    result.fill(0)
    check(HkdfSha256.derive(salt, ikm, info, expected.size).contentEquals(expected)) { "output aliases input" }
}

private inline fun reject(action: () -> Unit) {
    try {
        action()
        error("invalid argument was accepted")
    } catch (_: IllegalArgumentException) {
        // Expected.
    }
}

fun main() {
    val ikm = ByteArray(22) { 0x0b }
    checkDerivation(hex.parseHex("000102030405060708090a0b0c"), ikm, hex.parseHex("f0f1f2f3f4f5f6f7f8f9"),
        hex.parseHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        hex.parseHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
    checkDerivation(null, ikm, ByteArray(0),
        hex.parseHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
        hex.parseHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"))
    val random = Random(5869)
    fun bytes(size: Int) = ByteArray(size).also(random::nextBytes)
    var comparisons = 0
    for (saltSize in intArrayOf(0, 1, 32, 64, 65, 129)) {
        for (length in intArrayOf(0, 1, 31, 32, 33, 63, 64, 65, 127, 8159, 8160)) {
            val salt = bytes(saltSize)
            val input = bytes(length % 101)
            val info = bytes(length % 131)
            val prk = referenceMac(salt).doFinal(input)
            checkDerivation(salt, input, info, prk, referenceExpand(prk, info, length))
            comparisons++
        }
    }
    for (keySize in intArrayOf(33, 64, 65, 131)) {
        val key = bytes(keySize)
        val info = bytes(65)
        check(HkdfSha256.expand(key, info, 257).contentEquals(referenceExpand(key, info, 257)))
        comparisons++
    }
    reject { HkdfSha256.expand(ByteArray(31), ByteArray(0), 1) }
    reject { HkdfSha256.expand(ByteArray(32), ByteArray(0), -1) }
    reject { HkdfSha256.derive(null, ByteArray(0), ByteArray(0), 8161) }
    println("oracle=SunJCE ${referenceMac(null).provider.versionStr}")
    println("known_answers=2")
    println("differential_comparisons=$comparisons")
    println("max_output_and_rejection=passed")
}

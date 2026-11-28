package org.allbasket.abc.kdf.pbkdf2sha256.kotlin

import java.nio.ByteBuffer
import java.util.HexFormat
import java.util.Random
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private val hex = HexFormat.of()

private fun referenceMac(key: ByteArray): Mac =
    Mac.getInstance("HmacSHA256", "SunJCE").apply {
        init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
    }

private fun reference(password: ByteArray, salt: ByteArray, iterations: Int, size: Int): ByteArray {
    val mac = referenceMac(password)
    val output = ByteBuffer.allocate(size)
    val index = ByteBuffer.allocate(4)
    var blockNumber = 1
    while (output.hasRemaining()) {
        mac.update(salt)
        var previous = mac.doFinal(index.putInt(0, blockNumber).array())
        val block = previous.copyOf()
        repeat(iterations - 1) {
            previous = mac.doFinal(previous)
            for (i in block.indices) {
                block[i] = (block[i].toInt() xor previous[i].toInt()).toByte()
            }
        }
        output.put(block, 0, minOf(block.size, output.remaining()))
        blockNumber++
    }
    return output.array()
}

private fun checkDerivation(password: ByteArray, salt: ByteArray, iterations: Int, expected: ByteArray) {
    val beforePassword = password.copyOf()
    val beforeSalt = salt.copyOf()
    val output = Pbkdf2Sha256.derive(password, salt, iterations.toLong(), expected.size)
    check(output.contentEquals(expected)) { "PBKDF2 mismatch" }
    output.fill(0)
    check(password.contentEquals(beforePassword) && salt.contentEquals(beforeSalt)) { "input array changed" }
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
    checkDerivation("passwd".encodeToByteArray(), "salt".encodeToByteArray(), 1, hex.parseHex(
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    ))
    checkDerivation("Password".encodeToByteArray(), "NaCl".encodeToByteArray(), 80_000, hex.parseHex(
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" +
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
    ))
    val random = Random(8018)
    fun bytes(size: Int) = ByteArray(size).also(random::nextBytes)
    var comparisons = 0
    for (size in intArrayOf(1, 31, 32, 33, 63, 64, 65, 95, 257)) {
        for (passwordSize in intArrayOf(0, 1, 64, 65, 4096)) {
            val password = bytes(passwordSize)
            val salt = bytes(size % 97)
            val iterations = size % 17 + 1
            checkDerivation(password, salt, iterations, reference(password, salt, iterations, size))
            comparisons++
        }
    }
    val empty = ByteArray(0)
    reject { Pbkdf2Sha256.derive(empty, empty, 0, 1) }
    reject { Pbkdf2Sha256.derive(empty, empty, Pbkdf2Sha256.MAX_ITERATIONS + 1, 1) }
    reject { Pbkdf2Sha256.derive(empty, empty, 1, 0) }
    reject { Pbkdf2Sha256.derive(empty, empty, 1, -1) }
    println("oracle=SunJCE ${referenceMac(empty).provider.versionStr}")
    println("known_answers=2")
    println("differential_comparisons=$comparisons")
    println("invalid_iterations_and_output=passed")
}

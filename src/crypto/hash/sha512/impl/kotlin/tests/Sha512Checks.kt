package org.allbasket.abc.hash.sha512.kotlin

import java.security.MessageDigest
import java.util.HexFormat

private val hex = HexFormat.of()
private val oracle = MessageDigest.getInstance("SHA-512")

fun main() {
    val fixtures = listOf(
        ByteArray(0) to ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        "abc".encodeToByteArray() to ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ByteArray(1_000_000) { 97 } to ("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb" +
            "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"),
    )
    for ((message, expected) in fixtures) check(hex.formatHex(Sha512.hash(message)) == expected)
    var snapshots = 0
    var comparisons = 0
    val sizes = listOf(0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257, 1025)
    for (size in sizes) {
        val bytes = ByteArray(size + 11) { (it * it + 31 * it + 7).toByte() }
        val input = bytes.copyOfRange(11, bytes.size)
        val expected = oracle.digest(input)
        check(Sha512.hash(input).contentEquals(expected))
        comparisons++
        for (split in 0..size) {
            val stream = Sha512()
            val mutable = bytes.copyOf()
            stream.update(mutable, 11, split)
            mutable.fill(0)
            check(stream.digest().contentEquals(oracle.digest(input.copyOf(split))))
            stream.update(bytes, 11 + split, size - split)
            check(stream.digest().contentEquals(expected))
            snapshots += 2
        }
    }
    val stream = Sha512().update(byteArrayOf(97, 98))
    for ((offset, len) in listOf(-1 to 1, 1 to 1, 0 to -1, Int.MAX_VALUE to 1)) {
        check(runCatching { stream.update(byteArrayOf(99), offset, len) }.exceptionOrNull() is IllegalArgumentException)
    }
    check(hex.formatHex(stream.update(byteArrayOf(99)).digest()) == fixtures[1].second)
    stream.reset()
    check(hex.formatHex(stream.digest()) == fixtures[0].second)
    println("known_answers=${fixtures.size}")
    println("provider_comparisons=$comparisons")
    println("streaming_snapshots=$snapshots")
    println("oracle=${oracle.provider.name} ${oracle.provider.versionStr}")
    println("range_rejection_and_ownership=passed")
}

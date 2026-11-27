package org.allbasket.abc.mac.hmacsha256.kotlin

import java.util.HexFormat
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

private fun reference(key: ByteArray, input: ByteArray, length: Int = input.size): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    // The JDK rejects empty key objects. HMAC pads both input keys to the same block.
    val paddedKey = if (key.isEmpty()) ByteArray(64) else key
    mac.init(SecretKeySpec(paddedKey, "HmacSHA256"))
    mac.update(input, 0, length)
    return mac.doFinal()
}

private fun compare(key: ByteArray, input: ByteArray, tag: ByteArray): Int {
    check(HmacSha256.authenticate(key, input).contentEquals(tag)) { "One-shot tag mismatch" }
    val callerKey = key.copyOf()
    val stream = HmacSha256(callerKey)
    callerKey.fill(0xa5.toByte())
    val framed = ByteArray(input.size + 2) { 0x5a }
    input.copyInto(framed, 1)
    val middle = input.size / 2
    check(stream.update(framed, 1, middle).tag().contentEquals(reference(key, input, middle)))
    val before = stream.tag()
    try {
        stream.update(framed, 1, Int.MAX_VALUE)
        error("Invalid range accepted")
    } catch (_: IndexOutOfBoundsException) {
        check(stream.tag().contentEquals(before)) { "Invalid range changed state" }
    }
    stream.update(framed, middle + 1, input.size - middle).update(framed, framed.size, 0)
    check(stream.tag().contentEquals(tag)) { "Streaming tag mismatch" }
    stream.tag().fill(0)
    framed.fill(0)
    check(stream.tag().contentEquals(tag)) { "Caller storage aliased the state" }
    return 2
}

fun main() {
    val vectors = listOf(
        Triple(ByteArray(20) { 0x0b }, "Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        Triple("Jefe".encodeToByteArray(), "what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        Triple(ByteArray(131) { 0xaa.toByte() }, "Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    )
    var snapshots = 0
    for ((key, input, expected) in vectors) {
        snapshots += compare(key, input.encodeToByteArray(), HexFormat.of().parseHex(expected))
    }
    val random = Random(4231)
    var comparisons = 0
    for (keyLength in listOf(0, 1, 31, 32, 63, 64, 65, 131, 1024)) {
        for (length in listOf(0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 257, 1024)) {
            val key = random.nextBytes(keyLength)
            val input = random.nextBytes(length)
            snapshots += compare(key, input, reference(key, input))
            comparisons++
        }
    }
    val provider = Mac.getInstance("HmacSHA256").provider
    println("oracle=${provider.name} ${provider.versionStr}")
    println("known_answers=${vectors.size}")
    println("one_shot_comparisons=$comparisons")
    println("streaming_snapshots=$snapshots")
    println("invalid_range_and_ownership=passed")
}

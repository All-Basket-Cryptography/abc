package org.allbasket.abc.conformance.rfc8439

import org.allbasket.abc.cipher.chacha20.kotlin.ChaCha20

fun main(args: Array<String>) {
    val key = ByteArray(32) { it.toByte() }
    val nonce = decode("000000000000004a00000000")
    val blockNonce = decode("000000090000004a00000000")
    check(wire(ChaCha20.block(key, blockNonce, 1u)) ==
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    val encrypted = ChaCha20.xor(key, nonce, 1u, rfcMessage)
    check(wire(encrypted) ==
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
        "5af90bbf74a35be6b40b8eedf2785e42874d")
    ChaCha20.xorInto(key, nonce, 1u, encrypted, encrypted)
    check(encrypted.contentEquals(rfcMessage))

    for (counter in listOf(0u, 1u, UInt.MAX_VALUE - 1u, UInt.MAX_VALUE)) {
        val bound = ((1L shl 32) - counter.toLong()) * ChaCha20.BLOCK_BYTES
        check(!ChaCha20.fitsCounter(-1, counter))
        check(ChaCha20.fitsCounter(0, counter) && ChaCha20.fitsCounter(bound, counter))
        check(!ChaCha20.fitsCounter(bound + 1, counter))
    }
    val output = ByteArray(66) { 0xa9.toByte() }
    val saved = output.copyOf()
    rejects<IllegalArgumentException> { ChaCha20.xorInto(key, nonce, UInt.MAX_VALUE, ByteArray(65), output) }
    rejects<IllegalArgumentException> { ChaCha20.xorInto(key, nonce, 1u, ByteArray(67), output) }
    rejects<IllegalArgumentException> { ChaCha20.xorInto(key, ByteArray(11), 1u, ByteArray(5), output) }
    rejects<IllegalArgumentException> { ChaCha20.xorInto(ByteArray(31), nonce, 1u, ByteArray(5), output) }
    check(output.contentEquals(saved))
    ChaCha20.xorInto(key, nonce, UInt.MAX_VALUE, ByteArray(64), output)
    check(output.copyOf(64).contentEquals(ChaCha20.block(key, nonce, UInt.MAX_VALUE)))
    check(output.copyOfRange(64, 66).contentEquals(saved.copyOfRange(64, 66)))

    println("rfc=2")
    println("boundaries=passed")
    for ((wireKey, wireNonce, counter, message) in fixtures(args.single())) {
        val result = ChaCha20.xor(decode(wireKey), decode(wireNonce), counter.toUInt(), decode(message))
        println("result=" + wire(result))
    }
}

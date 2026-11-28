package org.allbasket.abc.conformance.rfc8439

import org.allbasket.abc.aead.chacha20poly1305.kotlin.ChaCha20Poly1305

fun main(args: Array<String>) {
    val key = ByteArray(32) { (128 + it).toByte() }
    val nonce = decode("070000004041424344454647")
    val aad = decode("50515253c0c1c2c3c4c5c6c7")
    val (ciphertext, tag) = ChaCha20Poly1305.seal(key, nonce, aad, rfcMessage)
    check(wire(ciphertext) ==
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
        "3ff4def08e4b7a9de576d26586cec64b6116")
    check(wire(tag) == "1ae10b594f09e26a7e902ecbd0600691")

    val destination = ByteArray(ciphertext.size + 9) { 0xa9.toByte() }
    val saved = destination.copyOf()
    for (i in tag.indices) {
        val bad = tag.copyOf()
        bad[i] = (bad[i].toInt() xor 1).toByte()
        check(!ChaCha20Poly1305.openInto(key, nonce, aad, ciphertext, bad, destination))
        val inPlace = ciphertext.copyOf()
        check(!ChaCha20Poly1305.openInto(key, nonce, aad, inPlace, bad, inPlace))
        check(inPlace.contentEquals(ciphertext))
    }
    val damaged = ciphertext.copyOf()
    damaged[0] = (damaged[0].toInt() xor 1).toByte()
    check(!ChaCha20Poly1305.openInto(key, nonce, aad, damaged, tag, destination))
    check(!ChaCha20Poly1305.openInto(key, nonce, ByteArray(0), ciphertext, tag, destination))
    check(!ChaCha20Poly1305.openInto(key, nonce, aad, ciphertext, ByteArray(15), destination))
    check(!ChaCha20Poly1305.openInto(key, nonce, aad, ciphertext, ByteArray(17), destination))
    rejects<IllegalArgumentException> {
        ChaCha20Poly1305.openInto(key, nonce, aad, ciphertext, tag, ByteArray(ciphertext.size - 1))
    }
    rejects<IllegalArgumentException> { ChaCha20Poly1305.openInto(ByteArray(31), nonce, aad, ciphertext, tag, destination) }
    rejects<IllegalArgumentException> { ChaCha20Poly1305.openInto(key, ByteArray(11), aad, ciphertext, tag, destination) }
    check(destination.contentEquals(saved))
    check(ChaCha20Poly1305.openInto(key, nonce, aad, ciphertext, tag, destination))
    check(destination.copyOf(ciphertext.size).contentEquals(rfcMessage))
    check(destination.copyOfRange(ciphertext.size, destination.size).contentEquals(saved.copyOfRange(ciphertext.size, saved.size)))
    val inPlace = ciphertext.copyOf()
    check(ChaCha20Poly1305.openInto(key, nonce, aad, inPlace, tag, inPlace))
    check(inPlace.contentEquals(rfcMessage))

    for ((wireKey, wireNonce, wireAad, wireMessage) in fixtures(args.single())) {
        val trialKey = decode(wireKey)
        val trialNonce = decode(wireNonce)
        val trialAad = decode(wireAad)
        val message = decode(wireMessage)
        val (encrypted, authenticator) = ChaCha20Poly1305.seal(trialKey, trialNonce, trialAad, message)
        val plain = ChaCha20Poly1305.open(trialKey, trialNonce, trialAad, encrypted, authenticator)
        check(plain != null && plain.contentEquals(message))
        println("result=" + wire(encrypted) + "\t" + wire(authenticator))
    }
    println("rfc=1")
    println("boundaries=passed")
}

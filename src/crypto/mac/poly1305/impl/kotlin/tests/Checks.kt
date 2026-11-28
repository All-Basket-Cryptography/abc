package org.allbasket.abc.conformance.rfc8439

import org.allbasket.abc.mac.poly1305.kotlin.Poly1305

fun main(args: Array<String>) {
    for ((index, fixture) in fixtures(args.single()).withIndex()) {
        val (wireKey, wireMessage, expected) = fixture
        val key = decode(wireKey)
        val message = decode(wireMessage)
        val tag = Poly1305.authenticate(key, message)
        check(wire(tag) == expected)
        val step = if (index < 8) 1 else 16
        for (split in 0..message.size step step) {
            Poly1305(key).use { mac ->
                mac.update(message, end = split)
                mac.update(ByteArray(0))
                mac.update(message, start = split)
                check(wire(mac.finish()) == expected)
            }
        }
        println("result=" + wire(tag))
    }

    rejects<IllegalArgumentException> { Poly1305(ByteArray(31)) }
    Poly1305(ByteArray(32)).use { mac ->
        rejects<IllegalArgumentException> { mac.update(ByteArray(1), start = -1) }
        rejects<IllegalArgumentException> { mac.update(ByteArray(1), end = 2) }
        mac.update(ByteArray(1))
        check(mac.finish().contentEquals(ByteArray(16)))
        rejects<IllegalStateException> { mac.finish() }
        rejects<IllegalStateException> { mac.update(ByteArray(1)) }
    }
    println("rfc=8")
    println("boundaries=passed")
}

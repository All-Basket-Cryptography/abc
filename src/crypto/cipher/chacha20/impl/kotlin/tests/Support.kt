package org.allbasket.abc.conformance.rfc8439

import java.io.File
import java.util.HexFormat

private val hexFormat = HexFormat.of()
val rfcMessage = decode(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a" +
        "204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f72207468" +
        "65206675747572652c2073756e73637265656e20776f756c642062652069742e",
)

fun decode(text: String): ByteArray = hexFormat.parseHex(text)
fun wire(bytes: ByteArray): String = hexFormat.formatHex(bytes)
fun fixtures(path: String): List<List<String>> = File(path).readLines().map { it.split('\t') }

inline fun <reified T : Throwable> rejects(action: () -> Unit) {
    try {
        action()
    } catch (failure: Throwable) {
        check(failure is T) { "Expected " + T::class.java.name + ", received " + failure }
        return
    }
    error("Expected " + T::class.java.name)
}

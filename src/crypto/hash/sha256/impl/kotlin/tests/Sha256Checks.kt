package org.allbasket.abc.hash.sha256.kotlin

import java.security.MessageDigest
import java.util.HexFormat
import kotlin.random.Random

private fun reference(oracle: MessageDigest, input: ByteArray, count: Int): ByteArray {
    oracle.update(input, 0, count)
    return oracle.digest()
}

private fun compare(oracle: MessageDigest, input: ByteArray, random: Random): Int {
    val expected = reference(oracle, input, input.size)
    check(Sha256.hash(input).contentEquals(expected)) { "One-shot mismatch at length ${input.size}" }

    val paddedInput = ByteArray(input.size + 2) { 0x5a }
    input.copyInto(paddedInput, 1)
    val streaming = Sha256().update(paddedInput, 1, 0)
    check(streaming.digest().contentEquals(reference(oracle, input, 0)))
    val chunkLimit = if (input.size <= 257) 32 else 8192
    var offset = 0
    var snapshots = 1
    while (offset < input.size) {
        val count = minOf(input.size - offset, random.nextInt(1, chunkLimit + 1))
        streaming.update(paddedInput, offset + 1, count)
        offset += count
        check(streaming.digest().contentEquals(reference(oracle, input, offset))) {
            "Streaming snapshot mismatch at prefix $offset of ${input.size}"
        }
        snapshots++
    }
    check(streaming.update(paddedInput, paddedInput.size, 0).digest().contentEquals(expected))
    check(paddedInput.first() == 0x5a.toByte() && paddedInput.last() == 0x5a.toByte())
    return snapshots
}

private inline fun <reified E : RuntimeException> expectFailure(action: () -> Unit) {
    try {
        action()
    } catch (error: RuntimeException) {
        check(error is E) { "Unexpected error type ${error.javaClass.name}" }
        return
    }
    error("Invalid input was accepted")
}

private fun checkValidation() {
    val abc = "abc".encodeToByteArray()
    val state = Sha256().update(abc, 0, 2)
    val before = state.digest()
    expectFailure<IndexOutOfBoundsException> { state.update(abc, -1, 2) }
    expectFailure<IndexOutOfBoundsException> { state.update(abc, 0, -1) }
    expectFailure<IndexOutOfBoundsException> { state.update(abc, 1, Int.MAX_VALUE) }
    expectFailure<IndexOutOfBoundsException> { state.update(abc, abc.size + 1, 0) }
    check(state.digest().contentEquals(before)) { "Invalid range changed streaming state" }
    check(state.update(abc, 2, 1).digest().contentEquals(Sha256.hash(abc)))

    val mutable = abc.copyOf()
    val owned = Sha256().update(mutable)
    mutable[0] = 0
    val result = owned.digest()
    result[0] = 0
    check(owned.digest().contentEquals(Sha256.hash(abc))) { "Caller array aliased the hash state" }

    val maximum = Sha256.MAX_MESSAGE_BYTES
    check(Sha256.checkedLength(maximum, 0) == maximum)
    check(Sha256.checkedLength(maximum - 1, 1) == maximum)
    expectFailure<IllegalArgumentException> { Sha256.checkedLength(maximum, 1) }
    expectFailure<IllegalArgumentException> { Sha256.checkedLength(maximum - 1, 2) }
}

fun main() {
    check(Runtime.version().feature() == 17) { "The qualification run requires JDK 17" }
    val oracle = MessageDigest.getInstance("SHA-256")
    val knownAnswers = listOf(
        ByteArray(0) to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "abc".encodeToByteArray() to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ByteArray(1_000_000) { 'a'.code.toByte() } to
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )
    val random = Random(216)
    var snapshots = 0
    for ((message, encoded) in knownAnswers) {
        check(Sha256.hash(message).contentEquals(HexFormat.of().parseHex(encoded)))
        snapshots += compare(oracle, message, random)
    }
    val boundaryLengths = intArrayOf(0, 1, 7, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121,
        127, 128, 129, 255, 256, 257, 1024, 4096, 65537, 1048576)
    for (length in boundaryLengths) {
        snapshots += compare(oracle, random.nextBytes(length), random)
    }
    val randomCases = 128
    repeat(randomCases) {
        snapshots += compare(oracle, random.nextBytes(random.nextInt(8193)), random)
    }
    checkValidation()
    println("runtime=${Runtime.version()}")
    println("architecture=${System.getProperty("os.arch")}")
    println("oracle=${oracle.provider.name} ${oracle.provider.versionStr}")
    println("known_answers=${knownAnswers.size}")
    println("one_shot_comparisons=${knownAnswers.size + boundaryLengths.size + randomCases}")
    println("streaming_snapshots=$snapshots")
    println("error_and_ownership_checks=passed")
}

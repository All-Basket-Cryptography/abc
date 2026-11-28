package org.allbasket.abc.hash.blake2b.kotlin

import java.util.HexFormat

private val hex = HexFormat.of()

fun main(args: Array<String>) {
    if (args.contentEquals(arrayOf("--benchmark"))) {
        benchmark()
        return
    }
    boundaryChecks()
    val lines = System.`in`.bufferedReader()
    var known = 0
    var openssl = 0
    var variable = 0
    var snapshots = 0
    var splits = 0
    while (true) {
        when (val role = lines.readLine() ?: break) {
            "known" -> known++
            "openssl" -> openssl++
            "variable" -> variable++
            else -> error("Unknown fixture role $role")
        }
        val input = hex.parseHex(checkNotNull(lines.readLine()))
        val expected = hex.parseHex(checkNotNull(lines.readLine()))
        val prefix = hex.parseHex(checkNotNull(lines.readLine()))
        val size = expected.size
        check(Blake2b.hash(input, size).contentEquals(expected)) { "one-shot fixture" }
        val stream = Blake2b(size)
        val middle = input.size / 2
        check(stream.update(input, 0, middle).digest().contentEquals(prefix)) { "prefix snapshot" }
        check(stream.update(input, middle).digest().contentEquals(expected)) { "continue after snapshot" }
        snapshots++
        if (input.size <= 257 && (size == 1 || size == 31 || size == 64)) {
            for (split in 0..input.size) {
                stream.reset()
                stream.update(input, 0, split).update(input, split, 0).update(input, split)
                check(stream.digest().contentEquals(expected)) { "two-chunk fixture" }
                splits++
            }
        }
    }
    check(known > 0 && openssl > 0 && variable > 0) { "missing fixtures" }
    println("known_answers=$known")
    println("openssl_comparisons=$openssl")
    println("hashlib_comparisons=$variable")
    println("snapshots=$snapshots")
    println("streaming_splits=$splits")
}

private fun boundaryChecks() {
    check(Blake2b().digestSize == 64)
    for (invalid in intArrayOf(-1, 0, 65)) {
        check(runCatching { Blake2b(invalid) }.exceptionOrNull() is IllegalArgumentException)
    }
    val original = ByteArray(129) { it.toByte() }
    val input = original.copyOf()
    val stream = Blake2b(31).update(input, 0, 128)
    val snapshot = Blake2b.hash(original.copyOf(128), 31)
    input.fill(0, 0, 128)
    check(stream.digest().contentEquals(snapshot)) { "pending input retained ownership" }
    for ((offset, length) in listOf(-1 to 1, 0 to -1, 128 to 2, Int.MAX_VALUE to 1)) {
        check(runCatching { stream.update(input, offset, length) }.exceptionOrNull() is IllegalArgumentException)
    }
    check(stream.digest().contentEquals(snapshot)) { "range rejection changed stream" }
    check(stream.update(input, 128).digest().contentEquals(Blake2b.hash(original, 31)))
    stream.reset()
    check(stream.digest().contentEquals(Blake2b.hash(ByteArray(0), 31)))

    val low = Blake2b::class.java.getDeclaredField("compressedLow").apply { isAccessible = true }
    val high = Blake2b::class.java.getDeclaredField("compressedHigh").apply { isAccessible = true }
    low.setLong(stream, -128L)
    high.setLong(stream, 5L)
    stream.update(input)
    check(low.getLong(stream) == 0L && high.getLong(stream) == 6L) { "counter carry" }
    stream.reset()
    low.setLong(stream, -128L)
    high.setLong(stream, -1L)
    stream.update(input, 0, 127)
    val maximum = stream.digest()
    check(runCatching { stream.update(input, 127, 1) }.exceptionOrNull() is ArithmeticException)
    check(stream.update(ByteArray(0)).digest().contentEquals(maximum)) { "overflow rollback" }
}

private fun benchmark() {
    val input = ByteArray(1 shl 20) { (37 * it + 11).toByte() }
    repeat(16) { Blake2b.hash(input) }
    var result = 0
    val rates = DoubleArray(7) {
        val start = System.nanoTime()
        repeat(16) { result = result xor Blake2b.hash(input)[0].toInt() }
        16e9 / (System.nanoTime() - start)
    }
    check(result == 0)
    println(rates.joinToString(","))
}

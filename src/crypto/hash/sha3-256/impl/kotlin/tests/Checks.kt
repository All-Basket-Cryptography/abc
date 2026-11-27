import java.security.MessageDigest
import java.util.HexFormat
import org.allbasket.abc.hash.sha3256.kotlin.Sha3_256

fun main() {
    val oracle = MessageDigest.getInstance("SHA3-256")
    var count = 0
    var splits = 0
    System.`in`.bufferedReader(Charsets.UTF_8).forEachLine { line ->
        val row = line.split(':')
        val input = HexFormat.of().parseHex(row[0])
        val expected = HexFormat.of().parseHex(row[1])
        check(Sha3_256.hash(input).contentEquals(expected))
        for (split in 0..input.size) {
            val hasher = Sha3_256()
            hasher.update(input, 0, split)
            oracle.update(input, 0, split)
            check(hasher.digest().contentEquals(oracle.digest()))
            hasher.update(input, split, 0)
            hasher.update(input, split, input.size - split)
            check(hasher.digest().contentEquals(expected))
            splits++
        }
        count++
    }
    val message = byteArrayOf(1, 2, 3)
    val expected = oracle.digest(message)
    val hasher = Sha3_256()
    hasher.update(message)
    message.fill(0)
    try {
        hasher.update(message, 2, 2)
        error("accepted invalid input range")
    } catch (_: IndexOutOfBoundsException) {
        check(hasher.digest().contentEquals(expected))
    }
    hasher.reset()
    check(hasher.digest().contentEquals(oracle.digest()))
    println("cases=$count")
    println("splits=$splits")
    println("jca=${oracle.provider.name}")
}

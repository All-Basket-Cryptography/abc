import java.util.HexFormat
import org.allbasket.abc.hash.shake256.kotlin.Shake256

fun main() {
    var count = 0
    var splits = 0
    System.`in`.bufferedReader(Charsets.UTF_8).forEachLine { line ->
        val row = line.split(':')
        val input = HexFormat.of().parseHex(row[0])
        val expected = HexFormat.of().parseHex(row[2])
        check(Shake256.hash(input, expected.size).contentEquals(expected))
        for (split in 0..input.size) {
            val absorber = Shake256()
            absorber.update(input, 0, split)
            absorber.update(input, split, 0)
            absorber.update(input, split, input.size - split)
            val reader = absorber.finish()
            val other = absorber.finish()
            absorber.reset()
            val actual = ByteArray(409)
            var offset = 0
            for (length in intArrayOf(0, 1, 134, 1, 136, 137)) {
                reader.readInto(actual, offset, length)
                offset += length
            }
            check(actual.contentEquals(expected))
            check(other.read(expected.size).contentEquals(expected))
            splits++
        }
        count++
    }
    val input = byteArrayOf(1, 2, 3)
    val expected = Shake256.hash(input, 200)
    val absorber = Shake256()
    absorber.update(input)
    input.fill(0)
    val reader = absorber.finish()
    try {
        reader.readInto(input, 2, 2)
        error("accepted invalid output range")
    } catch (_: IndexOutOfBoundsException) {
        check(reader.read(200).contentEquals(expected))
    }
    println("cases=$count")
    println("splits=$splits")
}

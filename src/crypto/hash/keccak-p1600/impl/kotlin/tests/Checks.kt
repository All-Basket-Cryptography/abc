import org.allbasket.abc.hash.keccakp1600.kotlin.KeccakSponge

fun main() {
    val expected = longArrayOf(
        0xf1258f7940e1dde7uL.toLong(), 0x84d5ccf933c0478auL.toLong(), 0xd598261ea65aa9eeuL.toLong(), 0xbd1547306f80494duL.toLong(), 0x8b284e056253d057uL.toLong(),
        0xff97a42d7f8e6fd4uL.toLong(), 0x90fee5a0a44647c4uL.toLong(), 0x8c5bda0cd6192e76uL.toLong(), 0xad30a6f71b19059cuL.toLong(), 0x30935ab7d08ffc64uL.toLong(),
        0xeb5aa93f2317d635uL.toLong(), 0xa9a6e6260d712103uL.toLong(), 0x81a57c16dbcf555fuL.toLong(), 0x43b831cd0347c826uL.toLong(), 0x01f22f1a11a5569fuL.toLong(),
        0x05e5635a21d9ae61uL.toLong(), 0x64befef28cc970f2uL.toLong(), 0x613670957bc46611uL.toLong(), 0xb87c5a554fd00ecbuL.toLong(), 0x8c3ee88a1ccf32c8uL.toLong(),
        0x940c7922ae3a2614uL.toLong(), 0x1841f924a2c509e4uL.toLong(), 0x16f53526e70465c2uL.toLong(), 0x75f644e97f30a13buL.toLong(), 0xeaf1ff7b5ceca249uL.toLong(),
    )
    val actual = LongArray(25)
    KeccakSponge.permute(actual)
    check(actual.contentEquals(expected)) { "XKCP zero-state permutation mismatch" }
    println("permutation_lanes=25")
}

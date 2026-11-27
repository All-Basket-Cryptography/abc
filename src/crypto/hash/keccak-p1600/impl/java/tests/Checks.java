import java.util.Arrays;

import org.allbasket.abc.hash.keccakp1600.KeccakSponge;

public final class Checks {
    public static void main(String[] args) {
        // First XKCP permutation of an all-zero state.
        long[] expected = {
            0xf1258f7940e1dde7L, 0x84d5ccf933c0478aL, 0xd598261ea65aa9eeL, 0xbd1547306f80494dL, 0x8b284e056253d057L,
            0xff97a42d7f8e6fd4L, 0x90fee5a0a44647c4L, 0x8c5bda0cd6192e76L, 0xad30a6f71b19059cL, 0x30935ab7d08ffc64L,
            0xeb5aa93f2317d635L, 0xa9a6e6260d712103L, 0x81a57c16dbcf555fL, 0x43b831cd0347c826L, 0x01f22f1a11a5569fL,
            0x05e5635a21d9ae61L, 0x64befef28cc970f2L, 0x613670957bc46611L, 0xb87c5a554fd00ecbL, 0x8c3ee88a1ccf32c8L,
            0x940c7922ae3a2614L, 0x1841f924a2c509e4L, 0x16f53526e70465c2L, 0x75f644e97f30a13bL, 0xeaf1ff7b5ceca249L,
        };
        long[] actual = new long[25];
        KeccakSponge.permute(actual);
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("XKCP zero-state permutation mismatch");
        }
        System.out.println("permutation_lanes=25");
    }
}

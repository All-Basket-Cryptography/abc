import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.allbasket.abc.cipher.chacha20.ChaCha20;

public final class Checks {
    private static final long LIMIT = 1L << 32;
    private static final HexFormat HEX = HexFormat.of();

    private static void check(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("ChaCha20 output mismatch");
        }
    }

    private static void expect(Class<? extends RuntimeException> type, Runnable action) {
        try {
            action.run();
        } catch (RuntimeException error) {
            if (type.isInstance(error)) {
                return;
            }
            throw error;
        }
        throw new AssertionError("Expected rejection for " + type.getName());
    }

    private static Cipher cipher(byte[] key, byte[] nonce, long counter) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new ChaCha20ParameterSpec(nonce, (int) counter));
        return cipher;
    }

    private static void vectors() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = HEX.parseHex("000000090000004a00000000");
        check(ChaCha20.block(key, nonce, 1), HEX.parseHex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"));
        nonce[3] = 0;
        byte[] input = HEX.parseHex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
            "637265656e20776f756c642062652069742e");
        try (ChaCha20 profile = new ChaCha20(key, nonce, 1)) {
            profile.apply(input, 0, 67);
            profile.apply(input, 67, input.length - 67);
        }
        check(input, HEX.parseHex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42874d"));
    }

    private static void boundary() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        Arrays.fill(key, (byte) 0x27);
        Arrays.fill(nonce, (byte) 0x48);
        long last = LIMIT - 1;
        byte[] reference = cipher(key, nonce, last).doFinal(new byte[64]);
        expect(IllegalArgumentException.class, () -> new ChaCha20(key, nonce, -1));
        expect(IllegalArgumentException.class, () -> new ChaCha20(key, nonce, LIMIT));
        expect(IllegalArgumentException.class, () -> new ChaCha20(new byte[31], nonce, 0));
        expect(IllegalArgumentException.class, () -> new ChaCha20(key, new byte[11], 0));
        try (ChaCha20 state = new ChaCha20(key, nonce, last)) {
            byte[] data = new byte[64];
            state.apply(data, 0, 31);
            if (state.remaining() != 33) {
                throw new AssertionError("Wrong remaining capacity after partial final block");
            }
            byte[] canary = data.clone();
            expect(IllegalStateException.class, () -> state.apply(data, 29, 34));
            expect(IndexOutOfBoundsException.class, () -> state.apply(data, Integer.MAX_VALUE, 1));
            check(data, canary);
            if (state.remaining() != 33) {
                throw new AssertionError("Rejected update spent capacity");
            }
            state.apply(data, 31, 33);
            check(data, reference);
            state.apply(data, data.length, 0);
            expect(IllegalStateException.class, () -> state.apply(data, 0, 1));
            if (state.remaining() != 0) {
                throw new AssertionError("Final block not exhausted");
            }
        }
        byte[] empty = new byte[0];
        ChaCha20 closed = new ChaCha20(key, nonce, 0);
        closed.close();
        closed.close();
        expect(IllegalStateException.class, () -> closed.apply(empty));
    }

    private static void compare() throws Exception {
        Random random = new Random(0x843920L);
        int cases = 0;
        int splits = 0;
        for (long counter : new long[] {0, 1, 31, 0x80000001L, LIMIT - 2, LIMIT - 1}) {
            for (int length : new int[] {0, 1, 63, 64, 65, 127, 128, 129, 257}) {
                if (length > (LIMIT - counter) * 64) {
                    continue;
                }
                byte[] key = new byte[32];
                byte[] nonce = new byte[12];
                byte[] input = new byte[length];
                random.nextBytes(key);
                random.nextBytes(nonce);
                random.nextBytes(input);
                byte[] expected = cipher(key, nonce, counter).doFinal(input);
                for (int split = 0; split <= length; split++, splits++) {
                    byte[] data = input.clone();
                    try (ChaCha20 state = new ChaCha20(key, nonce, counter)) {
                        state.apply(data, 0, split);
                        state.apply(data, split, 0);
                        state.apply(data, split, length - split);
                    }
                    check(data, expected);
                }
                cases++;
            }
        }
        for (int i = 0; i < 32; i++) {
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            byte[] input = new byte[129 + 149 * i];
            random.nextBytes(key);
            random.nextBytes(nonce);
            random.nextBytes(input);
            byte[] expected = cipher(key, nonce, i).doFinal(input);
            try (ChaCha20 state = new ChaCha20(key, nonce, i)) {
                Arrays.fill(key, (byte) 0);
                Arrays.fill(nonce, (byte) 0);
                state.apply(input, 0, 1);
                state.apply(input, 1, 65);
                state.apply(input, 66, input.length - 66);
            }
            check(input, expected);
            cases++;
        }
        System.out.println("provider=SunJCE");
        System.out.println("cases=" + cases);
        System.out.println("splits=" + splits);
    }

    public static void main(String[] args) throws Exception {
        vectors();
        boundary();
        compare();
    }
}

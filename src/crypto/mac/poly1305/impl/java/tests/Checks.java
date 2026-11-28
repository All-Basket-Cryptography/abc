import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import org.allbasket.abc.mac.poly1305.Poly1305;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();

    private static void check(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("Poly1305 tag mismatch");
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

    private static void lifecycle() {
        byte[] key = new byte[32];
        byte[] input = new byte[41];
        Arrays.fill(key, (byte) 0xff);
        Arrays.fill(input, (byte) 0xae);
        byte[] expected = Poly1305.authenticate(key, input);
        expect(IllegalArgumentException.class, () -> new Poly1305(new byte[31]));
        expect(IllegalArgumentException.class, () -> new Poly1305(new byte[33]));
        try (Poly1305 state = new Poly1305(key)) {
            Arrays.fill(key, (byte) 0);
            byte[] prefix = Arrays.copyOf(input, 15);
            state.update(prefix);
            Arrays.fill(prefix, (byte) 0);
            expect(IndexOutOfBoundsException.class, () -> state.update(input, Integer.MAX_VALUE, 1));
            expect(IndexOutOfBoundsException.class, () -> state.update(input, 0, -1));
            state.update(input, 15, input.length - 15);
            check(state.finish(), expected);
            expect(IllegalStateException.class, state::finish);
            expect(IllegalStateException.class, () -> state.update(input));
        }
        Poly1305 closed = new Poly1305(key);
        closed.close();
        closed.close();
        expect(IllegalStateException.class, closed::finish);
    }

    public static void main(String[] args) throws Exception {
        lifecycle();
        int cases = 0;
        int splits = 0;
        Random random = new Random(1305);
        try (var reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String line; (line = reader.readLine()) != null; cases++) {
                String[] parts = line.split(":", -1);
                byte[] key = HEX.parseHex(parts[0]);
                byte[] message = HEX.parseHex(parts[1]);
                byte[] expected = HEX.parseHex(parts[2]);
                check(Poly1305.authenticate(key, message), expected);
                try (Poly1305 state = new Poly1305(key)) {
                    for (int offset = 0; offset < message.length;) {
                        int count = Math.min(1 + random.nextInt(37), message.length - offset);
                        state.update(message, offset, count);
                        offset += count;
                    }
                    check(state.finish(), expected);
                }
                if (parts[3].equals("all")) {
                    for (int split = 0; split <= message.length; split++, splits++) {
                        try (Poly1305 state = new Poly1305(key)) {
                            state.update(message, 0, split);
                            state.update(message, split, 0);
                            state.update(message, split, message.length - split);
                            check(state.finish(), expected);
                        }
                    }
                }
            }
        }
        System.out.println("cases=" + cases);
        System.out.println("splits=" + splits);
    }
}

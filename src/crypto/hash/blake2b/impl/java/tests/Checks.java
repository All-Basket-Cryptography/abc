import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.hash.blake2b.Blake2b;

public final class Checks {
    private static void check(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("BLAKE2b digest mismatch");
        }
    }

    private static void expect(Class<? extends RuntimeException> type, Runnable task) {
        try {
            task.run();
        } catch (RuntimeException error) {
            if (type.isInstance(error)) {
                return;
            }
            throw error;
        }
        throw new AssertionError("Expected rejection for " + type.getName());
    }

    public static void main(String[] args) throws Exception {
        HexFormat hex = HexFormat.of();
        byte[] abc = "abc".getBytes(StandardCharsets.US_ASCII);
        check(Blake2b.hash(abc, 64), hex.parseHex(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d" +
            "87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"));
        if (Arrays.equals(Blake2b.hash(abc, 32), Arrays.copyOf(Blake2b.hash(abc, 64), 32))) {
            throw new AssertionError("Selected digest length was not bound into the initial state");
        }

        int cases = 0;
        int splits = 0;
        BufferedReader fixtures = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = fixtures.readLine()) != null; cases++) {
            String[] row = line.split(":", -1);
            byte[] message = hex.parseHex(row[0]);
            byte[] expected = hex.parseHex(row[1]);
            int size = expected.length;
            check(Blake2b.hash(message, size), expected);
            if (size != 1 && size != 31 && size != 64) {
                continue;
            }
            for (int split = 0; split <= message.length; split++, splits++) {
                Blake2b context = new Blake2b(size);
                context.update(message, 0, split);
                context.digest();
                context.update(message, split, 0);
                context.update(message, split, message.length - split);
                check(context.digest(), expected);
            }
        }
        validateBuffers();
        validateCounter();
        System.out.println("cases=" + cases);
        System.out.println("splits=" + splits);
    }

    private static void validateBuffers() {
        expect(IllegalArgumentException.class, () -> new Blake2b(0));
        expect(IllegalArgumentException.class, () -> new Blake2b(65));
        byte[] input = new byte[129];
        Arrays.fill(input, (byte) 7);
        byte[] first = Blake2b.hash(Arrays.copyOf(input, 128), 31);
        byte[] second = Blake2b.hash(input, 31);
        Blake2b context = new Blake2b(31);
        context.update(input, 0, 128);
        Arrays.fill(input, 0, 128, (byte) 0);
        expect(IndexOutOfBoundsException.class, () -> context.update(input, Integer.MAX_VALUE, 1));
        expect(IndexOutOfBoundsException.class, () -> context.update(input, 0, -1));
        check(context.digest(), first);
        context.update(input, 128, 1);
        check(context.digest(), second);
        context.reset();
        check(context.digest(), Blake2b.hash(new byte[0], 31));
    }

    private static void validateCounter() throws ReflectiveOperationException {
        Field used = Blake2b.class.getDeclaredField("used");
        Field high = Blake2b.class.getDeclaredField("lengthHigh");
        Field low = Blake2b.class.getDeclaredField("lengthLow");
        used.setAccessible(true);
        high.setAccessible(true);
        low.setAccessible(true);
        Blake2b context = new Blake2b(1);
        used.setInt(context, 127);
        low.setLong(context, -1);
        context.update(new byte[] {1});
        if (high.getLong(context) != 1 || low.getLong(context) != 0) {
            throw new AssertionError("BLAKE2b counter carry failed");
        }
        used.setInt(context, 126);
        high.setLong(context, -1);
        low.setLong(context, -2);
        context.update(new byte[] {1});
        byte[] before = context.digest();
        expect(ArithmeticException.class, () -> context.update(new byte[] {2}));
        context.update(new byte[0]);
        if (high.getLong(context) != -1 || low.getLong(context) != -1) {
            throw new AssertionError("BLAKE2b counter rejection modified the byte count");
        }
        check(context.digest(), before);
    }
}

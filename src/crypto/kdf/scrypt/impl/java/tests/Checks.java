import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.kdf.scrypt.Scrypt;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();

    private static void reject(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid scrypt input accepted");
    }

    private static long workspace(int cost, int block, int parallel) {
        long stride = 128L * block;
        return (cost + (long) parallel + 2) * stride + 128;
    }

    private static void boundaries() {
        reject(() -> Scrypt.workspaceSize(1, 1, 1));
        reject(() -> Scrypt.workspaceSize(3, 1, 1));
        reject(() -> Scrypt.workspaceSize(65536, 1, 1));
        reject(() -> Scrypt.workspaceSize(16, 0, 1));
        reject(() -> Scrypt.workspaceSize(16, 8, 0));
        reject(() -> Scrypt.workspaceSize(16, 8, Integer.MAX_VALUE));
        reject(() -> Scrypt.workspaceSize(1 << 30, Integer.MAX_VALUE, Integer.MAX_VALUE));
        reject(() -> Scrypt.workspaceSize(2, 4_000_000, 1));
        byte[] empty = new byte[0];
        reject(() -> Scrypt.derive(empty, empty, 2, 1, 1, 0, Long.MAX_VALUE));
        reject(() -> Scrypt.derive(empty, empty, 2, 1, 1, Integer.MAX_VALUE, Long.MAX_VALUE));
        reject(() -> Scrypt.derive(empty, empty, 2, 1, 1, 1, -1));
        if (Scrypt.workspaceSize(2, 1, 1) != 768 || Scrypt.workspaceSize(32768, 1, 1) != 4194816) {
            throw new AssertionError("Unexpected scrypt workspace size");
        }
    }

    public static void main(String[] args) throws Exception {
        boundaries();
        int cases = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String row; (row = input.readLine()) != null; cases++) {
                String[] fields = row.split(":", -1);
                byte[] password = HEX.parseHex(fields[0]);
                byte[] salt = HEX.parseHex(fields[1]);
                int cost = Integer.parseInt(fields[2]);
                int blockSize = Integer.parseInt(fields[3]);
                int parallel = Integer.parseInt(fields[4]);
                byte[] expected = HEX.parseHex(fields[5]);
                long minimum = workspace(cost, blockSize, parallel) + expected.length;
                if (Scrypt.workspaceSize(cost, blockSize, parallel) + (long) expected.length != minimum) {
                    throw new AssertionError("Wrong computed workspace size");
                }
                reject(() -> Scrypt.derive(password, salt, cost, blockSize, parallel, expected.length, minimum - 1));
                byte[] actual = Scrypt.derive(password, salt, cost, blockSize, parallel, expected.length, minimum);
                if (!Arrays.equals(actual, expected) ||
                        !Arrays.equals(password, HEX.parseHex(fields[0])) ||
                        !Arrays.equals(salt, HEX.parseHex(fields[1]))) {
                    throw new AssertionError("scrypt output or input preservation mismatch in case " + cases);
                }
            }
        }
        System.out.println("cases=" + cases);
        System.out.println("one_byte_under_budget_rejections=" + cases);
        System.out.println("malformed_parameters_rejected=11");
    }
}

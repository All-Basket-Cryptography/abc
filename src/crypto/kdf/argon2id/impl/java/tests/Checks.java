import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.kdf.argon2id.Argon2id;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();

    private static void reject(Runnable operation) {
        try {
            operation.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid Argon2id input accepted");
    }

    public static void main(String[] args) throws Exception {
        byte[] empty = new byte[0];
        reject(() -> Argon2id.workspaceBytes(8, 0));
        reject(() -> Argon2id.workspaceBytes(31, 4));
        reject(() -> Argon2id.workspaceBytes(Integer.MAX_VALUE, 1));
        reject(() -> Argon2id.workspaceBytes(Integer.MAX_VALUE, 1 << 24));
        reject(() -> Argon2id.derive(empty, new byte[7], empty, empty, 8, 1, 1, 4, Long.MAX_VALUE));
        reject(() -> Argon2id.derive(empty, new byte[8], empty, empty, 8, 0, 1, 4, Long.MAX_VALUE));
        reject(() -> Argon2id.derive(empty, new byte[8], empty, empty, 8, 1, 1, 3, Long.MAX_VALUE));

        int cases = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String line; (line = input.readLine()) != null; cases++) {
                String[] row = line.split(":", -1);
                int memory = Integer.parseInt(row[0]);
                int passes = Integer.parseInt(row[1]);
                int lanes = Integer.parseInt(row[2]);
                int length = Integer.parseInt(row[3]);
                byte[][] bytes = new byte[4][];
                for (int i = 0; i < bytes.length; i++) {
                    bytes[i] = HEX.parseHex(row[4 + i]);
                }
                long workspace = (memory - memory % (4L * lanes) + 5) * 1024;
                if (Argon2id.workspaceBytes(memory, lanes) != workspace) {
                    throw new AssertionError("Unexpected Argon2id workspace accounting");
                }
                reject(() -> Argon2id.derive(bytes[0], bytes[1], bytes[2], bytes[3],
                    memory, passes, lanes, length, workspace + length - 1));
                byte[] actual = Argon2id.derive(bytes[0], bytes[1], bytes[2], bytes[3],
                    memory, passes, lanes, length, workspace + length);
                if (!Arrays.equals(actual, HEX.parseHex(row[8]))) {
                    throw new AssertionError("Argon2id tag mismatch in case " + cases);
                }
                for (int i = 0; i < bytes.length; i++) {
                    if (!Arrays.equals(bytes[i], HEX.parseHex(row[4 + i]))) {
                        throw new AssertionError("Argon2id modified caller input");
                    }
                }
            }
        }
        System.out.println(cases);
    }
}

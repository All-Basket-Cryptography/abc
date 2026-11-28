import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.hash.sha3256.Sha3_256;

public final class Checks {
    private static void check(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("SHA3-256 mismatch");
        }
    }

    public static void main(String[] args) throws Exception {
        MessageDigest oracle = MessageDigest.getInstance("SHA3-256");
        int cases = 0;
        int splits = 0;
        BufferedReader fixtures = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = fixtures.readLine()) != null; cases++) {
            String[] row = line.split(":", -1);
            byte[] input = HexFormat.of().parseHex(row[0]);
            byte[] expected = HexFormat.of().parseHex(row[1]);
            check(Sha3_256.hash(input), expected);
            for (int split = 0; split <= input.length; split++, splits++) {
                Sha3_256 hasher = new Sha3_256();
                hasher.update(input, 0, split);
                oracle.update(input, 0, split);
                check(hasher.digest(), oracle.digest());
                hasher.update(input, split, 0);
                hasher.update(input, split, input.length - split);
                check(hasher.digest(), expected);
            }
        }
        byte[] bytes = {1, 2, 3};
        byte[] expected = oracle.digest(bytes);
        Sha3_256 hasher = new Sha3_256();
        hasher.update(bytes);
        Arrays.fill(bytes, (byte) 0);
        try {
            hasher.update(bytes, 2, 2);
            throw new AssertionError("accepted invalid input range");
        } catch (IndexOutOfBoundsException expectedError) {
            check(hasher.digest(), expected);
        }
        hasher.reset();
        check(hasher.digest(), oracle.digest());
        System.out.println("cases=" + cases);
        System.out.println("splits=" + splits);
        System.out.println("jca=" + oracle.getProvider().getName());
    }
}

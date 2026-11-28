import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.hash.keccakp1600.KeccakSponge;
import org.allbasket.abc.hash.shake256.Shake256;

public final class Checks {
    private static void check(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("SHAKE256 mismatch");
        }
    }

    public static void main(String[] args) throws Exception {
        int cases = 0;
        int splits = 0;
        BufferedReader fixtures = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = fixtures.readLine()) != null; cases++) {
            String[] row = line.split(":", -1);
            byte[] input = HexFormat.of().parseHex(row[0]);
            byte[] expected = HexFormat.of().parseHex(row[2]);
            check(Shake256.hash(input, expected.length), expected);
            for (int split = 0; split <= input.length; split++, splits++) {
                Shake256 absorber = new Shake256();
                absorber.update(input, 0, split);
                absorber.update(input, split, 0);
                absorber.update(input, split, input.length - split);
                KeccakSponge.Reader reader = absorber.finish();
                KeccakSponge.Reader other = absorber.finish();
                absorber.reset();
                byte[] actual = new byte[409];
                int offset = 0;
                for (int count : new int[] {0, 1, 134, 1, 136, 137}) {
                    reader.readInto(actual, offset, count);
                    offset += count;
                }
                check(actual, expected);
                check(other.read(expected.length), expected);
            }
        }
        byte[] bytes = {1, 2, 3};
        byte[] expected = Shake256.hash(bytes, 200);
        Shake256 absorber = new Shake256();
        absorber.update(bytes);
        Arrays.fill(bytes, (byte) 0);
        KeccakSponge.Reader reader = absorber.finish();
        try {
            reader.readInto(bytes, 2, 2);
            throw new AssertionError("accepted invalid output range");
        } catch (IndexOutOfBoundsException expectedError) {
            check(reader.read(200), expected);
        }
        System.out.println("cases=" + cases);
        System.out.println("splits=" + splits);
    }
}

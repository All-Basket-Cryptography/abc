import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.cipher.aes256.Aes256;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    private static void invalid(Action action) throws Exception {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid length accepted");
    }

    private static void same(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("AES-256 block mismatch");
        }
    }

    private static void rejectsReplacementProvider() throws Exception {
        Provider original = Security.getProvider("SunJCE");
        int position = Arrays.asList(Security.getProviders()).indexOf(original) + 1;
        Security.removeProvider("SunJCE");
        try {
            Security.insertProviderAt(new Provider("SunJCE", "17", "Test shadow provider") {
                private static final long serialVersionUID = 1L;
            }, 1);
            try {
                new Aes256(new byte[32]);
            } catch (NoSuchProviderException expected) {
                return;
            }
            throw new AssertionError("Unexpected provider accepted");
        } finally {
            Security.removeProvider("SunJCE");
            Security.insertProviderAt(original, position);
        }
    }

    public static void main(String[] args) throws Exception {
        for (int size : new int[] {0, 16, 24, 31, 33}) {
            invalid(() -> new Aes256(new byte[size]));
        }
        Aes256 cipher = new Aes256(new byte[32]);
        for (int size : new int[] {0, 15, 17, 32}) {
            invalid(() -> cipher.encryptBlock(new byte[size]));
            invalid(() -> cipher.decryptBlock(new byte[size]));
        }
        rejectsReplacementProvider();
        int cases = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String row; (row = input.readLine()) != null; cases++) {
                String[] fields = row.split(":");
                byte[] key = HEX.parseHex(fields[0]);
                byte[] plaintext = HEX.parseHex(fields[1]);
                byte[] decryptionInput = HEX.parseHex(fields[2]);
                byte[] encryption = HEX.parseHex(fields[3]);
                byte[] decryption = HEX.parseHex(fields[4]);
                Aes256 c = new Aes256(key);
                Arrays.fill(key, (byte) 0x65);
                same(c.encryptBlock(plaintext), encryption);
                same(c.decryptBlock(decryptionInput), decryption);
                same(c.decryptBlock(encryption), plaintext);
                same(c.encryptBlock(decryption), decryptionInput);
                same(plaintext, HEX.parseHex(fields[1]));
                same(decryptionInput, HEX.parseHex(fields[2]));
            }
        }
        System.out.println("cases=" + cases);
        System.out.println("provider_replacements_rejected=1");
    }
}

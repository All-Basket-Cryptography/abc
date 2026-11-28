import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.aead.aes256gcm.Aes256Gcm;

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

    private static byte[] changed(byte[] array, int index) {
        byte[] copy = array.clone();
        copy[index] ^= (byte) 0x80;
        return copy;
    }

    private static void same(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("AES-256-GCM output mismatch");
        }
    }

    private static void reject(Aes256Gcm context, byte[] nonce, byte[] aad, byte[] body, byte[] tag) throws Exception {
        byte[] before = body.clone();
        if (context.open(nonce, aad, body, tag) != null) {
            throw new AssertionError("Invalid AES-256-GCM input produced plaintext");
        }
        same(body, before);
    }

    private static int tamper() throws Exception {
        Aes256Gcm context = new Aes256Gcm(new byte[32]);
        byte[] nonce = new byte[12];
        byte[] aad = new byte[19];
        byte[] message = new byte[65];
        var sealed = context.seal(nonce, aad, message);
        for (int i = 0; i < 16; i++) {
            reject(context, nonce, aad, sealed.ciphertext(), changed(sealed.tag(), i));
        }
        reject(context, nonce, aad, sealed.ciphertext(), new byte[15]);
        reject(context, nonce, aad, sealed.ciphertext(), new byte[17]);
        reject(context, changed(nonce, 11), aad, sealed.ciphertext(), sealed.tag());
        reject(context, nonce, changed(aad, 18), sealed.ciphertext(), sealed.tag());
        reject(context, nonce, aad, changed(sealed.ciphertext(), 64), sealed.tag());
        reject(context, nonce, aad, Arrays.copyOf(sealed.ciphertext(), 64), sealed.tag());
        reject(new Aes256Gcm(changed(new byte[32], 1)), nonce, aad, sealed.ciphertext(), sealed.tag());
        invalid(() -> new Aes256Gcm(new byte[31]));
        invalid(() -> new Aes256Gcm(new byte[33]));
        invalid(() -> context.seal(new byte[11], aad, message));
        invalid(() -> context.open(new byte[13], aad, sealed.ciphertext(), sealed.tag()));
        if (Aes256Gcm.MAX_PAYLOAD_BYTES != 68719476704L ||
                Aes256Gcm.MAX_ARRAY_PAYLOAD_BYTES != Integer.MAX_VALUE - 16) {
            throw new AssertionError("Unexpected payload limits");
        }
        return 23;
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
                new Aes256Gcm(new byte[32]);
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
        rejectsReplacementProvider();
        int cases = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String row; (row = input.readLine()) != null; cases++) {
                String[] fields = row.split(":", -1);
                byte[] key = HEX.parseHex(fields[0]);
                byte[] nonce = HEX.parseHex(fields[1]);
                byte[] aad = HEX.parseHex(fields[2]);
                byte[] message = HEX.parseHex(fields[3]);
                byte[] body = HEX.parseHex(fields[4]);
                byte[] tag = HEX.parseHex(fields[5]);
                Aes256Gcm context = new Aes256Gcm(key);
                Arrays.fill(key, (byte) 0x65);
                var sealed = context.seal(nonce, aad, message);
                same(sealed.ciphertext(), body);
                same(sealed.tag(), tag);
                same(context.open(nonce, aad, body, tag), message);
                same(message, HEX.parseHex(fields[3]));
                same(body, HEX.parseHex(fields[4]));
            }
        }
        System.out.println("cases=" + cases);
        System.out.println("authentication_rejections=" + tamper());
        System.out.println("provider_replacements_rejected=1");
    }
}

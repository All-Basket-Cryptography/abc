import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.aead.chacha20poly1305.ChaCha20Poly1305;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();

    private static void same(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("ChaCha20-Poly1305 output mismatch");
        }
    }

    private static void reject(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag) {
        byte[] before = ciphertext.clone();
        if (ChaCha20Poly1305.open(key, nonce, aad, ciphertext, tag) != null) {
            throw new AssertionError("Invalid ciphertext produced plaintext");
        }
        same(ciphertext, before);
    }

    private static void invalid(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid key or nonce length accepted");
    }

    private static byte[] changed(byte[] data, int index) {
        byte[] mutated = data.clone();
        mutated[index] ^= (byte) 0x80;
        return mutated;
    }

    private static void check(String[] fixture) {
        byte[] key = HEX.parseHex(fixture[0]);
        byte[] nonce = HEX.parseHex(fixture[1]);
        byte[] aad = HEX.parseHex(fixture[2]);
        byte[] message = HEX.parseHex(fixture[3]);
        byte[] expected = HEX.parseHex(fixture[4]);
        byte[] tag = HEX.parseHex(fixture[5]);
        byte[] original = message.clone();
        ChaCha20Poly1305.Sealed sealed = ChaCha20Poly1305.seal(key, nonce, aad, message);
        same(sealed.ciphertext(), expected);
        same(sealed.tag(), tag);
        same(message, original);
        byte[] opened = ChaCha20Poly1305.open(key, nonce, aad, expected, tag);
        same(opened, original);
        same(expected, HEX.parseHex(fixture[4]));
        if (sealed.ciphertext() == message || opened == expected) {
            throw new AssertionError("Result exposes a caller input buffer");
        }
    }

    private static int tamper() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[17];
        byte[] message = new byte[65];
        var sealed = ChaCha20Poly1305.seal(key, nonce, aad, message);
        byte[] ciphertext = sealed.ciphertext();
        byte[] tag = sealed.tag();
        for (int i = 0; i < tag.length; i++) {
            reject(key, nonce, aad, ciphertext, changed(tag, i));
        }
        reject(key, nonce, aad, ciphertext, new byte[15]);
        reject(key, nonce, aad, ciphertext, new byte[17]);
        reject(changed(key, 15), nonce, aad, ciphertext, tag);
        reject(key, changed(nonce, 11), aad, ciphertext, tag);
        reject(key, nonce, changed(aad, 16), ciphertext, tag);
        reject(key, nonce, aad, changed(ciphertext, 64), tag);
        reject(key, nonce, aad, Arrays.copyOf(ciphertext, 64), tag);
        invalid(() -> ChaCha20Poly1305.seal(new byte[31], nonce, aad, message));
        invalid(() -> ChaCha20Poly1305.seal(key, new byte[13], aad, message));
        invalid(() -> ChaCha20Poly1305.open(new byte[33], nonce, aad, ciphertext, tag));
        invalid(() -> ChaCha20Poly1305.open(key, new byte[11], aad, ciphertext, tag));
        if (ChaCha20Poly1305.MAX_PAYLOAD_BYTES != 274877906880L) {
            throw new AssertionError("Incorrect IETF counter limit");
        }
        return tag.length + 7;
    }

    public static void main(String[] args) throws Exception {
        int cases = 0;
        try (var reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String line; (line = reader.readLine()) != null; cases++) {
                check(line.split(":", -1));
            }
        }
        System.out.println("cases=" + cases);
        System.out.println("authentication_rejections=" + tamper());
    }
}

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

import org.allbasket.abc.agreement.x25519.X25519;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    private static void same(byte[] actual, byte[] expected) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError("X25519 output mismatch: " +
                (actual == null ? "unexpected rejection" : HEX.formatHex(actual)));
        }
    }

    private static void invalid(Action action) throws Exception {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid X25519 width accepted");
    }

    private static void knownAnswers() throws Exception {
        byte[] alice = HEX.parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bob = HEX.parseHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] alicePublic = HEX.parseHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] bobPublic = HEX.parseHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] expected = HEX.parseHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        same(X25519.publicKey(alice), alicePublic);
        same(X25519.publicKey(bob), bobPublic);
        same(X25519.sharedSecret(alice, bobPublic), expected);
        same(X25519.sharedSecret(bob, alicePublic), expected);
        byte[] scalar = new byte[32];
        scalar[0] = 9;
        byte[] u = scalar;
        for (int i = 1; i <= 1000; i++) {
            byte[] next = X25519.sharedSecret(scalar, u);
            if (next == null) {
                throw new AssertionError("Unexpected RFC iteration rejection");
            }
            u = scalar;
            scalar = next;
            if (i == 1) {
                same(scalar, HEX.parseHex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
            }
        }
        same(scalar, HEX.parseHex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
    }

    private static void profile() throws Exception {
        byte[] scalar = new byte[32];
        Arrays.fill(scalar, (byte) 0x7c);
        byte[] expected = X25519.publicKey(scalar);
        byte[] alias = new byte[32];
        Arrays.fill(alias, (byte) 0xff);
        alias[0] = (byte) 246;
        same(X25519.sharedSecret(scalar, alias), expected);
        alias[31] &= 0x7f;
        same(X25519.sharedSecret(scalar, alias), expected);
        alias = new byte[32];
        alias[0] = 9;
        alias[31] = (byte) 0x80;
        same(X25519.sharedSecret(scalar, alias), expected);
        for (int i = 0; i < 32; i++) {
            alias = scalar.clone();
            alias[0] = (byte) ((alias[0] & 0xf8) | (i & 7));
            alias[31] = (byte) ((alias[31] & 0x3f) | ((i >>> 3) << 6));
            same(X25519.publicKey(alias), expected);
        }
        String[] lowOrder = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        };
        for (String wire : lowOrder) {
            byte[] u = HEX.parseHex(wire);
            same(X25519.sharedSecret(scalar, u), null);
            u[31] |= (byte) 0x80;
            same(X25519.sharedSecret(scalar, u), null);
        }
        for (int size : new int[] {0, 31, 33, 56}) {
            invalid(() -> X25519.publicKey(new byte[size]));
            invalid(() -> X25519.sharedSecret(new byte[size], scalar));
            invalid(() -> X25519.sharedSecret(scalar, new byte[size]));
        }
    }

    private static void rejectProviderReplacement() throws Exception {
        Provider original = Security.getProvider("SunEC");
        int position = Arrays.asList(Security.getProviders()).indexOf(original) + 1;
        Security.removeProvider("SunEC");
        try {
            Security.insertProviderAt(new Provider("SunEC", "17", "Test shadow provider") {
                private static final long serialVersionUID = 1L;
            }, 1);
            try {
                X25519.publicKey(new byte[32]);
            } catch (NoSuchProviderException expected) {
                return;
            }
            throw new AssertionError("Unexpected provider accepted");
        } finally {
            Security.removeProvider("SunEC");
            Security.insertProviderAt(original, position);
        }
    }

    public static void main(String[] args) throws Exception {
        knownAnswers();
        profile();
        rejectProviderReplacement();
        int cases = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String row; (row = input.readLine()) != null; cases++) {
                String[] fields = row.split(":");
                byte[] scalar = HEX.parseHex(fields[0]);
                byte[] u = HEX.parseHex(fields[1]);
                same(X25519.publicKey(scalar), HEX.parseHex(fields[2]));
                same(X25519.sharedSecret(scalar, u), HEX.parseHex(fields[3]));
                same(scalar, HEX.parseHex(fields[0]));
                same(u, HEX.parseHex(fields[1]));
            }
        }
        System.out.println("cases=" + cases);
        System.out.println("rfc_known_answers=6");
        System.out.println("private_clamp_aliases=32");
        System.out.println("peer_aliases=3");
        System.out.println("low_order_rejections=14");
        System.out.println("provider_replacements_rejected=1");
    }
}

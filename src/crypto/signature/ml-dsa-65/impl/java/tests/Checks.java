import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.signers.MLDSASigner;

import org.allbasket.abc.signature.mldsa65.MlDsa65;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();
    private static final int HINT_OFFSET = 3248;
    private static final int HINTS = 55;

    private static void require(boolean result, String reason) {
        if (!result) {
            throw new AssertionError(reason);
        }
    }

    private static void strictHints() throws Exception {
        byte[] seed = new byte[32];
        byte[] empty = new byte[0];
        byte[] pub = MlDsa65.publicKey(seed);
        byte[] sig = MlDsa65.sign(seed, empty, empty);
        require(MlDsa65.verify(pub, empty, empty, sig), "Empty context and message not supported");
        require(!MlDsa65.verify(pub, empty, new byte[256], sig), "Oversized context accepted");
        require(!MlDsa65.verify(pub, empty, empty, new byte[3308]), "Truncated signature accepted");
        require(!MlDsa65.verify(pub, empty, empty, new byte[3310]), "Extended signature accepted");
        require(!MlDsa65.verify(new byte[1951], empty, empty, sig), "Truncated public key accepted");
        require(!MlDsa65.verify(new byte[1953], empty, empty, sig), "Extended public key accepted");
        try {
            MlDsa65.sign(seed, empty, new byte[256]);
            throw new AssertionError("Oversized signing context accepted");
        } catch (IllegalArgumentException expected) {
            // The public guard rejected the context before key expansion.
        }
        try {
            MlDsa65.publicKey(new byte[4032]);
            throw new AssertionError("An expanded key was accepted as a seed");
        } catch (IllegalArgumentException expected) {
            // The production SDK only accepts seeds.
        }

        var hints = MlDsa65.class.getDeclaredMethod("canonicalHints", byte[].class);
        hints.setAccessible(true);
        Object owner = Modifier.isStatic(hints.getModifiers()) ? null : MlDsa65.class.getField("INSTANCE").get(null);
        require((boolean) hints.invoke(owner, sig), "Generated signature failed hint check");
        byte[] zero = new byte[3309];
        require((boolean) hints.invoke(owner, zero), "Empty hint section is noncanonical");
        byte[] full = zero.clone();
        Arrays.fill(full, HINT_OFFSET + HINTS, full.length, (byte) HINTS);
        for (int i = 0; i < HINTS; i++) {
            full[HINT_OFFSET + i] = (byte) i;
        }
        require((boolean) hints.invoke(owner, full), "Maximum ordered hint section is noncanonical");
        byte[] backwards = full.clone();
        backwards[backwards.length - 1] = 54;
        byte[] oversized = full.clone();
        oversized[oversized.length - 1] = 56;
        byte[] duplicate = full.clone();
        duplicate[HINT_OFFSET + 1] = duplicate[HINT_OFFSET];
        byte[] unordered = full.clone();
        unordered[HINT_OFFSET] = 2;
        byte[] nonzeroTail = zero.clone();
        nonzeroTail[HINT_OFFSET + HINTS - 1] = 1;
        for (byte[] malformed : new byte[][] {backwards, oversized, duplicate, unordered, nonzeroTail}) {
            require(!(boolean) hints.invoke(owner, malformed), "Malformed hint section accepted");
            require(!MlDsa65.verify(pub, empty, empty, malformed), "Malformed signature accepted");
        }
    }

    private static void acvp(String[] row) throws Exception {
        switch (row[0]) {
        case "keygen":
            var pub = MlDsa65.publicKey(HEX.parseHex(row[1]));
            require(HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(pub)).equals(row[2]),
                    "ACVP key generation mismatch");
            break;
        case "expanded-sign":
            byte[] message = HEX.parseHex(row[3]);
            byte[] context = HEX.parseHex(row[4]);
            byte[] signature = HEX.parseHex(row[5]);
            var secretKey = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, HEX.parseHex(row[1]));
            try {
                var signer = new MLDSASigner();
                signer.init(true, new ParametersWithContext(secretKey, context));
                signer.update(message, 0, message.length);
                require(Arrays.equals(signature, signer.generateSignature()), "ACVP expanded-key signature mismatch");
            } finally {
                secretKey.destroy();
            }
            require(MlDsa65.verify(HEX.parseHex(row[2]), message, context, signature), "ACVP expected signature rejected");
            break;
        case "verify":
            require(MlDsa65.verify(HEX.parseHex(row[1]), HEX.parseHex(row[2]),
                    HEX.parseHex(row[3]), HEX.parseHex(row[4])) == Boolean.parseBoolean(row[5]),
                    "ACVP verification mismatch");
            break;
        default:
            throw new AssertionError("Unexpected ACVP operation");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args[0].equals("acvp")) {
            strictHints();
        }
        int count = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String line; (line = input.readLine()) != null; count++) {
                String[] row = line.split(":", -1);
                switch (args[0]) {
                case "acvp":
                    acvp(row);
                    break;
                case "sign":
                    byte[] seed = HEX.parseHex(row[0]);
                    byte[] original = seed.clone();
                    byte[] message = HEX.parseHex(row[1]);
                    byte[] ctx = HEX.parseHex(row[2]);
                    byte[] pub = MlDsa65.publicKey(seed);
                    byte[] signature = MlDsa65.sign(seed, message, ctx);
                    require(Arrays.equals(seed, original), "Provider erasure modified caller seed");
                    require(Arrays.equals(signature, MlDsa65.sign(seed, message, ctx)), "Signing was nondeterministic");
                    require(MlDsa65.verify(pub, message, ctx, signature), "Generated signature did not verify");
                    require(!MlDsa65.verify(pub, message, Arrays.copyOf(ctx, ctx.length != 0 ? 0 : 1), signature),
                            "Wrong binary context verified");
                    System.out.println(HEX.formatHex(pub) + ":" + HEX.formatHex(signature));
                    break;
                case "verify":
                    require(MlDsa65.verify(HEX.parseHex(row[0]), HEX.parseHex(row[1]),
                            HEX.parseHex(row[2]), HEX.parseHex(row[3])), "OpenSSL signature rejected");
                    break;
                default:
                    throw new AssertionError("Unexpected consumer mode");
                }
            }
        }
        if (!args[0].equals("sign")) {
            System.out.println(count);
        }
    }
}

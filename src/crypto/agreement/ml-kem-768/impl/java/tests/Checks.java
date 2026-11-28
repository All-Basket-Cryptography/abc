import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

import org.allbasket.abc.agreement.mlkem768.MlKem768;

public final class Checks {
    private static final HexFormat HEX = HexFormat.of();
    private static final MLKEMParameters PROVIDER = MLKEMParameters.ml_kem_768;

    private static void same(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("ML-KEM-768 output mismatch");
        }
    }

    private static void reject(Class<? extends RuntimeException> expected, Runnable operation) {
        try {
            operation.run();
        } catch (RuntimeException error) {
            if (expected.isInstance(error)) {
                return;
            }
            throw error;
        }
        throw new AssertionError("ML-KEM-768 rejected input was accepted");
    }

    private static void lifecycle() {
        reject(IllegalArgumentException.class, () -> MlKem768.fromSeed(new byte[63]));
        reject(IllegalArgumentException.class, () -> MlKem768.fromSeed(new byte[65]));
        reject(IllegalArgumentException.class, () -> MlKem768.encapsulate(new byte[1183]));
        reject(IllegalArgumentException.class, () -> MlKem768.encapsulate(new byte[1185]));
        for (int i = 0; i < 4; i++) {
            try (var key = MlKem768.generateKey()) {
                var encapsulated = MlKem768.encapsulate(key.publicKey());
                same(encapsulated.secret(), key.decapsulate(encapsulated.ciphertext()));
                reject(IllegalArgumentException.class, () -> key.decapsulate(new byte[1087]));
                reject(IllegalArgumentException.class, () -> key.decapsulate(new byte[1089]));
                byte[] noncanonical = key.publicKey();
                noncanonical[0] = 1;
                noncanonical[1] = (byte) ((noncanonical[1] & 0xf0) | 13); // first coefficient is q
                reject(IllegalArgumentException.class, () -> MlKem768.encapsulate(noncanonical));
                byte[] second = key.publicKey();
                second[1] = (byte) ((second[1] & 15) | 16);
                second[2] = (byte) 0xd0; // second coefficient is q
                reject(IllegalArgumentException.class, () -> MlKem768.encapsulate(second));
            }
        }
        byte[] seed = new byte[64];
        var closed = MlKem768.fromSeed(seed);
        closed.close();
        closed.close();
        same(seed, new byte[64]);
        reject(IllegalStateException.class, closed::publicKey);
        reject(IllegalStateException.class, () -> closed.decapsulate(new byte[1088]));
    }

    private static void acvp(String[] row) throws Exception {
        switch (row[0]) {
        case "keygen":
            byte[] seed = HEX.parseHex(row[1]);
            try (var key = MlKem768.fromSeed(seed)) {
                Arrays.fill(seed, (byte) 0);
                same(HEX.parseHex(row[2]), key.publicKey());
            }
            break;
        case "encap":
            var publicKey = new MLKEMPublicKeyParameters(PROVIDER, HEX.parseHex(row[1]));
            var actual = MLKEMGenerator.internalGenerateEncapsulated(publicKey, HEX.parseHex(row[2]));
            try {
                same(HEX.parseHex(row[3]), actual.getEncapsulation());
                same(HEX.parseHex(row[4]), actual.getSecret());
            } finally {
                actual.destroy();
            }
            break;
        case "decap":
            var secretKey = new MLKEMPrivateKeyParameters(PROVIDER, HEX.parseHex(row[1]));
            try {
                same(HEX.parseHex(row[3]), new MLKEMExtractor(secretKey).extractSecret(HEX.parseHex(row[2])));
            } finally {
                secretKey.destroy();
            }
            break;
        case "reject_ek":
            reject(IllegalArgumentException.class, () -> MlKem768.encapsulate(HEX.parseHex(row[1])));
            break;
        default:
            throw new AssertionError("Unexpected ML-KEM-768 fixture");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args[0].equals("acvp")) {
            lifecycle();
        }
        int count = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
            for (String line; (line = input.readLine()) != null; count++) {
                String[] row = line.split(":", -1);
                switch (args[0]) {
                case "acvp":
                    acvp(row);
                    break;
                case "encapsulate":
                    try (var key = MlKem768.fromSeed(HEX.parseHex(row[0]))) {
                        byte[] publicKey = key.publicKey();
                        var actual = MlKem768.encapsulate(publicKey);
                        same(actual.secret(), key.decapsulate(actual.ciphertext()));
                        System.out.println(HEX.formatHex(publicKey) + ":" + HEX.formatHex(actual.ciphertext()) +
                            ":" + HEX.formatHex(actual.secret()));
                    }
                    break;
                case "decapsulate":
                    try (var key = MlKem768.fromSeed(HEX.parseHex(row[0]))) {
                        same(HEX.parseHex(row[2]), key.decapsulate(HEX.parseHex(row[1])));
                    }
                    break;
                default:
                    throw new AssertionError("Unexpected consumer mode");
                }
            }
        }
        if (!args[0].equals("encapsulate")) {
            System.out.println(count);
        }
    }
}

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.allbasket.abc.Sha256;

class Consumer {
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        byte[] abc = "abc".getBytes(StandardCharsets.UTF_8);
        byte[] digest = HexFormat.of().parseHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        require(Sha256.implementation().equals("sha256-abc-rust-portable"), "provider identity");
        require(Arrays.equals(Sha256.digest(abc), digest), "known answer");
        try (Sha256 state = new Sha256()) {
            state.update(new byte[] { 'a' });
            state.update(new byte[] { 'b', 'c' });
            require(Arrays.equals(state.finish(), digest), "stream known answer");
            try {
                state.finish();
                throw new AssertionError("second finish accepted");
            } catch (IllegalStateException expected) { }
            state.reset();
            require(Arrays.equals(state.finish(), Sha256.digest(new byte[0])), "reset");
        }
        try {
            Sha256.digest(null);
            throw new AssertionError("null input accepted");
        } catch (NullPointerException expected) { }
        System.out.println("External Java SHA-256 consumer passed");
    }
}

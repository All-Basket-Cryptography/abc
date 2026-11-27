package org.allbasket.abc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/** Research byte-oriented SHA-256, using the ABC native provider. */
public final class Sha256 implements AutoCloseable {
    static {
        loadNative();
    }

    private static void loadNative() {
        if ("Dalvik".equals(System.getProperty("java.vm.name"))
                || "Android Runtime".equals(System.getProperty("java.runtime.name"))) {
            System.loadLibrary("abc_android");
            return;
        }
        if (!System.getProperty("os.name").startsWith("Windows") || !System.getProperty("os.arch").equals("amd64")) {
            throw new UnsupportedOperationException("This ABC artifact targets Windows amd64");
        }
        try {
            Path directory = Files.createTempDirectory("abc-sha256-");
            directory.toFile().deleteOnExit();
            load(directory, "abc_crypto.dll");
            load(directory, "abc_java.dll");
        } catch (IOException failure) {
            throw new ExceptionInInitializerError(failure);
        }
    }

    private static void load(Path directory, String filename) throws IOException {
        Path library = directory.resolve(filename);
        try (InputStream input = Sha256.class.getResourceAsStream("/native/windows-amd64/" + filename)) {
            if (input == null) throw new IOException("Missing bundled library " + filename);
            Files.copy(input, library);
        }
        library.toFile().deleteOnExit();
        System.load(library.toAbsolutePath().toString());
    }

    private long handle;

    public Sha256() {
        long[] result = new long[1];
        check(newContext(result));
        handle = result[0];
        if (handle == 0) throw new IllegalStateException("Native provider returned a null context");
    }

    public static native String implementation();

    public static byte[] digest(byte[] input) {
        Objects.requireNonNull(input, "input");
        byte[] output = new byte[32];
        check(hash(input, output));
        return output;
    }

    public synchronized void update(byte[] input) {
        Objects.requireNonNull(input, "input");
        check(append(active(), input));
    }

    public synchronized byte[] finish() {
        byte[] output = new byte[32];
        check(finalizeDigest(active(), output));
        return output;
    }

    public synchronized void reset() {
        check(resetContext(active()));
    }

    @Override public synchronized void close() {
        if (handle != 0) {
            long old = handle;
            handle = 0;
            check(drop(old));
        }
    }

    private long active() {
        if (handle == 0) throw new IllegalStateException("SHA-256 context is closed");
        return handle;
    }

    private static void check(int status) {
        switch (status) {
            case 0: return;
            case 1, 2, 4: throw new IllegalArgumentException("ABC SHA-256 input error " + status);
            case 5: throw new OutOfMemoryError("ABC SHA-256 allocation failed");
            default: throw new IllegalStateException("ABC SHA-256 native status " + status);
        }
    }

    private static native int newContext(long[] output);
    private static native int hash(byte[] input, byte[] output);
    private static native int append(long context, byte[] input);
    private static native int finalizeDigest(long context, byte[] output);
    private static native int resetContext(long context);
    private static native int drop(long context);
}

package org.allbasket.abc.kdf.argon2id;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** RFC 9106 Argon2id version 1.3 with byte inputs and an explicit memory budget. */
public final class Argon2id {
    private static final int MAX_LANES = (1 << 24) - 1;
    private static final int FILL_BLOCKS = 4;

    private Argon2id() {}

    /** Return the configured provider's block payload and one temporary block in bytes. */
    public static long workspaceBytes(int memoryKiB, int lanes) {
        if (lanes < 1 || lanes > MAX_LANES || memoryKiB < 8L * lanes) {
            throw new IllegalArgumentException("Argon2id requires valid lane count and at least 8 KiB per lane");
        }
        int sliceGroup = 4 * lanes;
        int rounded = memoryKiB - memoryKiB % sliceGroup;
        if (rounded > Integer.MAX_VALUE - FILL_BLOCKS) {
            throw new IllegalArgumentException("Argon2id working block count exceeds the provider's representation");
        }
        return 1024L * (1L + Argon2BytesGenerator.getBlockCount(memoryKiB, lanes));
    }

    /** Return an owned tag after accounting for the provider's workspace and tag bytes. */
    public static byte[] derive(byte[] password, byte[] salt, byte[] secret, byte[] associatedData,
            int memoryKiB, int passes, int lanes, int tagLength, long memoryLimit) {
        long workspace = workspaceBytes(memoryKiB, lanes);
        if (passes < 1 || salt.length < 8 || tagLength < 4) {
            throw new IllegalArgumentException("Argon2id requires positive passes, an 8-byte salt and a 4-byte tag minimum");
        }
        if (memoryLimit < workspace + tagLength) {
            throw new IllegalArgumentException("Argon2id workspace and tag exceed the memory budget");
        }

        var builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id);
        try {
            var parameters = builder.withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(memoryKiB).withIterations(passes).withParallelism(lanes)
                .withSalt(salt).withSecret(secret).withAdditional(associatedData).build();
            try {
                var generator = new Argon2BytesGenerator();
                generator.init(parameters);
                byte[] tag = new byte[tagLength];
                generator.generateBytes(password, tag);
                return tag;
            } finally {
                parameters.clear();
            }
        } finally {
            builder.clear();
        }
    }
}

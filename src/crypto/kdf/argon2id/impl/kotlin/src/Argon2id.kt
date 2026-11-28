package org.allbasket.abc.kdf.argon2id.kotlin

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/** RFC 9106 Argon2id version 1.3 with byte inputs and an explicit memory budget. */
object Argon2id {
    private const val MAX_LANES = (1 shl 24) - 1
    private const val FILL_BLOCKS = 4

    /** Return the configured provider's block payload and one temporary block in bytes. */
    @JvmStatic
    fun workspaceBytes(memoryKiB: Int, lanes: Int): Long {
        require(lanes in 1..MAX_LANES && memoryKiB >= 8L * lanes) {
            "Argon2id requires valid lane count and at least 8 KiB per lane"
        }
        val sliceGroup = 4 * lanes
        val rounded = memoryKiB - memoryKiB % sliceGroup
        require(rounded <= Int.MAX_VALUE - FILL_BLOCKS) {
            "Argon2id working block count exceeds the provider's representation"
        }
        return 1024L * (1L + Argon2BytesGenerator.getBlockCount(memoryKiB, lanes))
    }

    /** Return an owned tag after accounting for the provider's workspace and tag bytes. */
    @JvmStatic
    fun derive(password: ByteArray, salt: ByteArray, secret: ByteArray, associatedData: ByteArray,
               memoryKiB: Int, passes: Int, lanes: Int, tagLength: Int, memoryLimit: Long): ByteArray {
        val workspace = workspaceBytes(memoryKiB, lanes)
        require(passes > 0 && salt.size >= 8 && tagLength >= 4) {
            "Argon2id requires positive passes, an 8-byte salt and a 4-byte tag minimum"
        }
        require(memoryLimit >= workspace + tagLength) { "Argon2id workspace and tag exceed the memory budget" }
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        try {
            val parameters = builder.withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(memoryKiB).withIterations(passes).withParallelism(lanes)
                .withSalt(salt).withSecret(secret).withAdditional(associatedData).build()
            try {
                val generator = Argon2BytesGenerator()
                generator.init(parameters)
                val tag = ByteArray(tagLength)
                generator.generateBytes(password, tag)
                return tag
            } finally {
                parameters.clear()
            }
        } finally {
            builder.clear()
        }
    }
}

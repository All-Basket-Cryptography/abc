package org.allbasket.abc.android

import org.allbasket.abc.Sha256 as NativeSha256

/** Android research SHA-256 backed by the ABC C ABI. */
class Sha256 : AutoCloseable {
    private val native = NativeSha256()

    fun update(input: ByteArray) = native.update(input)
    fun finish(): ByteArray = native.finish()
    fun reset() = native.reset()
    override fun close() = native.close()

    companion object {
        fun digest(input: ByteArray): ByteArray = NativeSha256.digest(input)
        fun implementation(): String = NativeSha256.implementation()
    }
}

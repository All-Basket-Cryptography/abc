package org.allbasket.abc.kdf.scrypt.kotlin

import java.lang.invoke.MethodHandles
import java.nio.ByteOrder
import org.allbasket.abc.kdf.pbkdf2sha256.kotlin.Pbkdf2Sha256

/** RFC 7914 byte-oriented scrypt with a caller-specified memory limit. */
object Scrypt {
    private const val MAX_ARRAY_BYTES = Int.MAX_VALUE - 8
    private const val STATE_WORDS = 16
    private val word = MethodHandles.byteArrayViewVarHandle(IntArray::class.java, ByteOrder.LITTLE_ENDIAN)

    /** Return the combined byte count of the primary work arrays. */
    @JvmStatic
    fun workspaceSize(cost: Int, blockSize: Int, parallel: Int): Int =
        layout(cost, blockSize, parallel).workspace

    /** Derive an owned result, validating the work-array and output budget first. */
    @JvmStatic
    fun derive(password: ByteArray, salt: ByteArray, cost: Int, blockSize: Int,
               parallel: Int, length: Int, memoryLimit: Long): ByteArray {
        val sizes = layout(cost, blockSize, parallel)
        require(length in 1..MAX_ARRAY_BYTES) {
            "scrypt requires a positive representable output length"
        }
        require(memoryLimit >= sizes.workspace.toLong() + length) {
            "scrypt work arrays and output exceed the memory limit"
        }
        val history = IntArray(sizes.table / Int.SIZE_BYTES)
        val lane = IntArray(sizes.stride / Int.SIZE_BYTES)
        val reordered = IntArray(lane.size)
        val state = IntArray(STATE_WORDS)
        val scratch = IntArray(STATE_WORDS)
        val data = Pbkdf2Sha256.derive(password, salt, 1, sizes.lanes)
        try {
            for (offset in data.indices step sizes.stride) {
                for (i in lane.indices) {
                    lane[i] = word.get(data, offset + i * Int.SIZE_BYTES) as Int
                }
                romix(lane, reordered, history, state, scratch, cost)
                for (i in lane.indices) {
                    word.set(data, offset + i * Int.SIZE_BYTES, lane[i])
                }
            }
            return Pbkdf2Sha256.derive(password, data, 1, length)
        } finally {
            data.fill(0)
            history.fill(0)
            lane.fill(0)
            reordered.fill(0)
            state.fill(0)
            scratch.fill(0)
        }
    }

    private class Layout(val stride: Int, val lanes: Int, val table: Int, val workspace: Int)

    private fun layout(cost: Int, blockSize: Int, parallel: Int): Layout {
        require(cost >= 2 && blockSize >= 1 && parallel >= 1 && (cost and (cost - 1)) == 0 &&
            cost.countTrailingZeroBits() < 16L * blockSize) {
            "scrypt requires positive r and p and power-of-two N below 2^(16r)"
        }
        val stride = 128L * blockSize
        require(stride <= MAX_ARRAY_BYTES / cost && stride <= MAX_ARRAY_BYTES / parallel) {
            "scrypt work arrays exceed the JVM profile size"
        }
        val lanes = stride * parallel
        val table = stride * cost
        val workspace = table + lanes + 2 * stride + 128
        require(workspace <= MAX_ARRAY_BYTES) { "scrypt work arrays exceed the JVM profile size" }
        return Layout(stride.toInt(), lanes.toInt(), table.toInt(), workspace.toInt())
    }

    private fun romix(input: IntArray, reordered: IntArray, history: IntArray, state: IntArray,
                      scratch: IntArray, cost: Int) {
        var lane = input
        var next = reordered
        val words = input.size
        for (i in 0 until cost) {
            lane.copyInto(history, i * words)
            blockMix(lane, next, state, scratch)
            val previous = lane
            lane = next
            next = previous
        }
        repeat(cost) {
            // N fits in one word, so only the low word of Integerify is needed.
            val slot = (lane[words - STATE_WORDS] and (cost - 1)) * words
            for (i in lane.indices) {
                lane[i] = lane[i] xor history[slot + i]
            }
            blockMix(lane, next, state, scratch)
            val previous = lane
            lane = next
            next = previous
        }
        // The 2*N exchanges place the final result back in input.
    }

    private fun blockMix(input: IntArray, output: IntArray, state: IntArray, scratch: IntArray) {
        val blocks = input.size / STATE_WORDS
        input.copyInto(state, 0, input.size - STATE_WORDS)
        for (block in 0 until blocks) {
            val offset = block * STATE_WORDS
            for (i in state.indices) {
                state[i] = state[i] xor input[offset + i]
            }
            salsa8(state, scratch)
            val position = (block / 2 + (block and 1) * (blocks / 2)) * STATE_WORDS
            state.copyInto(output, position)
        }
    }

    private fun salsa8(state: IntArray, scratch: IntArray) {
        state.copyInto(scratch)
        repeat(4) {
            quarter(scratch, 0, 4, 8, 12)
            quarter(scratch, 5, 9, 13, 1)
            quarter(scratch, 10, 14, 2, 6)
            quarter(scratch, 15, 3, 7, 11)
            quarter(scratch, 0, 1, 2, 3)
            quarter(scratch, 5, 6, 7, 4)
            quarter(scratch, 10, 11, 8, 9)
            quarter(scratch, 15, 12, 13, 14)
        }
        for (i in state.indices) {
            state[i] += scratch[i]
        }
    }

    private fun quarter(words: IntArray, a: Int, b: Int, c: Int, d: Int) {
        words[b] = words[b] xor (words[a] + words[d]).rotateLeft(7)
        words[c] = words[c] xor (words[b] + words[a]).rotateLeft(9)
        words[d] = words[d] xor (words[c] + words[b]).rotateLeft(13)
        words[a] = words[a] xor (words[d] + words[c]).rotateLeft(18)
    }
}

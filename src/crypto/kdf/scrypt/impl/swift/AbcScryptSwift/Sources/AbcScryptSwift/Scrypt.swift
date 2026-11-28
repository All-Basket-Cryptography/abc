import AbcPbkdf2Sha256Swift

/// RFC 7914 scrypt with same-language PBKDF2 and one reusable ROMix table.
public enum Scrypt {
    public enum InputError: Error, Equatable {
        case parameters, outputLength, workingArrays, memoryLimit
    }

    private static let maxBytes = 0x7fff_ffff
    private static let wordsPerBlock = 16

    private struct Layout {
        let lane: Int
        let data: Int
        let table: Int
        let work: Int
    }

    private static func layout(cost: Int, blockSize: Int, parallel: Int) throws -> Layout {
        guard cost > 1, cost & (cost - 1) == 0, blockSize > 0, parallel > 0 else {
            throw InputError.parameters
        }
        guard blockSize <= maxBytes / 128 else { throw InputError.workingArrays }
        let logCost = Int.bitWidth - 1 - cost.leadingZeroBitCount
        guard logCost < blockSize * 16 else { throw InputError.parameters }
        let lane = blockSize * 128
        guard parallel <= maxBytes / lane, cost <= maxBytes / lane else {
            throw InputError.workingArrays
        }
        let data = lane * parallel
        let table = lane * cost
        var work = 128
        for width in [data, table, lane, lane] {
            guard width <= maxBytes - work else { throw InputError.workingArrays }
            work += width
        }
        return Layout(lane: lane, data: data, table: table, work: work)
    }

    public static func workspaceSize(cost: Int, blockSize: Int, parallel: Int) throws -> Int {
        try layout(cost: cost, blockSize: blockSize, parallel: parallel).work
    }

    public static func derive(password: [UInt8], salt: [UInt8], cost: Int, blockSize: Int,
                              parallel: Int, length: Int, memoryLimit: Int) throws -> [UInt8] {
        let plan = try layout(cost: cost, blockSize: blockSize, parallel: parallel)
        guard length > 0, length <= maxBytes else { throw InputError.outputLength }
        guard memoryLimit >= plan.work, length <= memoryLimit - plan.work else { throw InputError.memoryLimit }

        let width = plan.lane / 4
        var history = [UInt32](repeating: 0, count: plan.table / 4)
        var lane = [UInt32](repeating: 0, count: width)
        var reordered = [UInt32](repeating: 0, count: width)
        var state = [UInt32](repeating: 0, count: wordsPerBlock)
        var scratch = [UInt32](repeating: 0, count: wordsPerBlock)
        var data = try Pbkdf2Sha256.derive(password: password, salt: salt, iterations: 1, length: plan.data)
        defer {
            for i in data.indices { data[i] = 0 }
            for i in history.indices { history[i] = 0 }
            for i in lane.indices { lane[i] = 0; reordered[i] = 0 }
            for i in state.indices { state[i] = 0; scratch[i] = 0 }
        }

        for offset in stride(from: 0, to: plan.data, by: plan.lane) {
            for i in lane.indices {
                let index = offset + 4 * i
                lane[i] = UInt32(data[index]) | (UInt32(data[index + 1]) << 8)
                    | (UInt32(data[index + 2]) << 16) | (UInt32(data[index + 3]) << 24)
            }
            for row in 0..<cost {
                let position = row * width
                for i in lane.indices { history[position + i] = lane[i] }
                blockMix(&lane, &reordered, &state, &scratch)
            }
            for _ in 0..<cost {
                // The allocation cap bounds every valid N below 2^32.
                let row = Int(lane[width - wordsPerBlock] & UInt32(cost - 1))
                let position = row * width
                for i in lane.indices { lane[i] ^= history[position + i] }
                blockMix(&lane, &reordered, &state, &scratch)
            }
            for i in lane.indices {
                let index = offset + 4 * i
                for j in 0..<4 { data[index + j] = UInt8(truncatingIfNeeded: lane[i] >> (8 * j)) }
            }
        }
        return try Pbkdf2Sha256.derive(password: password, salt: data, iterations: 1, length: length)
    }

    private static func blockMix(_ lane: inout [UInt32], _ reordered: inout [UInt32],
                                 _ state: inout [UInt32], _ scratch: inout [UInt32]) {
        let blocks = lane.count / wordsPerBlock
        let last = lane.count - wordsPerBlock
        for i in state.indices { state[i] = lane[last + i] }
        for block in 0..<blocks {
            let offset = block * wordsPerBlock
            for i in state.indices { state[i] ^= lane[offset + i] }
            salsa8(&state, &scratch)
            let position = (block / 2 + (block % 2) * (blocks / 2)) * wordsPerBlock
            for i in state.indices { reordered[position + i] = state[i] }
        }
        swap(&lane, &reordered)
    }

    @inline(__always)
    private static func rotate(_ value: UInt32, _ amount: Int) -> UInt32 {
        (value << amount) | (value >> (32 - amount))
    }

    @inline(__always)
    private static func quarter(_ words: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        words[b] ^= rotate(words[a] &+ words[d], 7)
        words[c] ^= rotate(words[b] &+ words[a], 9)
        words[d] ^= rotate(words[c] &+ words[b], 13)
        words[a] ^= rotate(words[d] &+ words[c], 18)
    }

    private static func salsa8(_ state: inout [UInt32], _ scratch: inout [UInt32]) {
        for i in state.indices { scratch[i] = state[i] }
        for _ in 0..<4 {
            quarter(&scratch, 0, 4, 8, 12)
            quarter(&scratch, 5, 9, 13, 1)
            quarter(&scratch, 10, 14, 2, 6)
            quarter(&scratch, 15, 3, 7, 11)
            quarter(&scratch, 0, 1, 2, 3)
            quarter(&scratch, 5, 6, 7, 4)
            quarter(&scratch, 10, 11, 8, 9)
            quarter(&scratch, 15, 12, 13, 14)
        }
        for i in state.indices { state[i] = state[i] &+ scratch[i] }
    }
}

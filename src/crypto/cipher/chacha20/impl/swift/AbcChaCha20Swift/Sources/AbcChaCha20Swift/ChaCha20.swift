public enum ChaCha20Error: Error, Equatable {
    case invalidKey
    case invalidNonce
    case counterExhausted
    case destinationTooShort
}

public enum ChaCha20 {
    public static let keyBytes = 32
    public static let nonceBytes = 12
    public static let blockBytes = 64

    public static func fitsCounter(_ size: UInt64, _ counter: UInt32) -> Bool {
        size <= ((1 << 32) - UInt64(counter)) * UInt64(blockBytes)
    }

    public static func block(key: [UInt8], nonce: [UInt8], counter: UInt32) throws -> [UInt8] {
        let initial = try initialize(key, nonce, counter)
        var work = [UInt32](repeating: 0, count: 16)
        var output = [UInt8](repeating: 0, count: blockBytes)
        compress(initial, work: &work, output: &output)
        return output
    }

    public static func xor(key: [UInt8], nonce: [UInt8], counter: UInt32,
                           input: [UInt8]) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: input.count)
        try xorInto(key: key, nonce: nonce, counter: counter, input: input, output: &output)
        return output
    }

    public static func xorInto(key: [UInt8], nonce: [UInt8], counter: UInt32, input: [UInt8],
                               output: inout [UInt8]) throws {
        guard fitsCounter(UInt64(input.count), counter) else { throw ChaCha20Error.counterExhausted }
        guard output.count >= input.count else { throw ChaCha20Error.destinationTooShort }
        var initial = try initialize(key, nonce, counter)
        var work = [UInt32](repeating: 0, count: 16)
        var stream = [UInt8](repeating: 0, count: blockBytes)
        var consumed = 0
        while consumed < input.count {
            initial[12] = counter + UInt32(consumed / blockBytes)
            compress(initial, work: &work, output: &stream)
            let count = min(blockBytes, input.count - consumed)
            for i in 0..<count {
                output[consumed + i] = input[consumed + i] ^ stream[i]
            }
            consumed += count
        }
    }

    private static func load(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        var word: UInt32 = 0
        for i in 0..<4 { word |= UInt32(bytes[offset + i]) << (8 * i) }
        return word
    }

    private static func initialize(_ key: [UInt8], _ nonce: [UInt8], _ counter: UInt32) throws -> [UInt32] {
        guard key.count == keyBytes else { throw ChaCha20Error.invalidKey }
        guard nonce.count == nonceBytes else { throw ChaCha20Error.invalidNonce }
        var words: [UInt32] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        words.reserveCapacity(16)
        for i in 0..<8 { words.append(load(key, 4 * i)) }
        words.append(counter)
        for i in 0..<3 { words.append(load(nonce, 4 * i)) }
        return words
    }

    private static func rotate(_ word: UInt32, _ count: Int) -> UInt32 {
        (word << count) | (word >> (32 - count))
    }

    private static func quarter(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] = state[a] &+ state[b]
        state[d] = rotate(state[d] ^ state[a], 16)
        state[c] = state[c] &+ state[d]
        state[b] = rotate(state[b] ^ state[c], 12)
        state[a] = state[a] &+ state[b]
        state[d] = rotate(state[d] ^ state[a], 8)
        state[c] = state[c] &+ state[d]
        state[b] = rotate(state[b] ^ state[c], 7)
    }

    private static func compress(_ initial: [UInt32], work: inout [UInt32], output: inout [UInt8]) {
        for i in initial.indices { work[i] = initial[i] }
        for _ in 0..<10 {
            quarter(&work, 0, 4, 8, 12)
            quarter(&work, 1, 5, 9, 13)
            quarter(&work, 2, 6, 10, 14)
            quarter(&work, 3, 7, 11, 15)
            quarter(&work, 0, 5, 10, 15)
            quarter(&work, 1, 6, 11, 12)
            quarter(&work, 2, 7, 8, 13)
            quarter(&work, 3, 4, 9, 14)
        }
        for i in work.indices {
            let word = work[i] &+ initial[i]
            for j in 0..<4 { output[4 * i + j] = UInt8(truncatingIfNeeded: word >> (8 * j)) }
        }
    }
}

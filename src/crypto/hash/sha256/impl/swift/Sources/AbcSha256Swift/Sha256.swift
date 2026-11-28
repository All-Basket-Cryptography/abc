/// Whole-byte SHA-256 with native Swift arithmetic and value-semantic state.
public struct Sha256 {
    public enum InputError: Error, Equatable {
        case invalidRange
        case messageTooLong
    }

    public static let digestBytes = 32
    public static let maxMessageBytes: UInt64 = (UInt64(1) << 61) - 1
    private static let blockBytes = 64
    private static let initial: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]
    private static let constants: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    private var state = Sha256.initial
    private var schedule = [UInt32](repeating: 0, count: 64)
    private var buffer = [UInt8](repeating: 0, count: 64)
    private var buffered = 0
    private var totalBytes: UInt64 = 0

    public init() {}

    public static func hash(_ input: [UInt8]) throws -> [UInt8] {
        var state = Sha256()
        try state.update(input)
        return state.digest()
    }

    public mutating func update(_ input: [UInt8]) throws {
        try update(input, offset: 0, length: input.count)
    }

    /// Append a validated input slice. Validation errors preserve the state.
    public mutating func update(_ input: [UInt8], offset: Int, length: Int) throws {
        guard offset >= 0, length >= 0, offset <= input.count, length <= input.count - offset else {
            throw InputError.invalidRange
        }
        totalBytes = try Self.checkedLength(totalBytes, UInt64(length))
        var cursor = offset
        var remaining = length
        if buffered != 0 {
            let copied = min(remaining, Self.blockBytes - buffered)
            buffer.replaceSubrange(buffered..<(buffered + copied), with: input[cursor..<(cursor + copied)])
            buffered += copied
            if buffered < Self.blockBytes {
                return
            }
            let block = buffer
            Self.compress(&state, &schedule, block, 0)
            cursor += copied
            remaining -= copied
        }
        while remaining >= Self.blockBytes {
            Self.compress(&state, &schedule, input, cursor)
            cursor += Self.blockBytes
            remaining -= Self.blockBytes
        }
        buffer.replaceSubrange(0..<remaining, with: input[cursor..<(cursor + remaining)])
        buffered = remaining
    }

    static func checkedLength(_ previous: UInt64, _ added: UInt64) throws -> UInt64 {
        guard added <= maxMessageBytes - previous else {
            throw InputError.messageTooLong
        }
        return previous + added
    }

    /// Return an owned digest snapshot while keeping the message available for later updates.
    public func digest() -> [UInt8] {
        let paddingBlocks = buffered < 56 ? 1 : 2
        var padded = [UInt8](repeating: 0, count: paddingBlocks * Self.blockBytes)
        padded.replaceSubrange(0..<buffered, with: buffer.prefix(buffered))
        padded[buffered] = 0x80
        let bitLength = totalBytes << 3
        for i in 0..<8 {
            padded[padded.count - 1 - i] = UInt8(truncatingIfNeeded: bitLength >> (i * 8))
        }
        var finalState = state
        var finalSchedule = [UInt32](repeating: 0, count: 64)
        for offset in stride(from: 0, to: padded.count, by: Self.blockBytes) {
            Self.compress(&finalState, &finalSchedule, padded, offset)
        }
        var output: [UInt8] = []
        output.reserveCapacity(Self.digestBytes)
        for word in finalState {
            output.append(UInt8(truncatingIfNeeded: word >> 24))
            output.append(UInt8(truncatingIfNeeded: word >> 16))
            output.append(UInt8(truncatingIfNeeded: word >> 8))
            output.append(UInt8(truncatingIfNeeded: word))
        }
        return output
    }

    private static func rotateRight(_ word: UInt32, _ amount: Int) -> UInt32 {
        (word >> amount) | (word << (32 - amount))
    }

    private static func compress(_ chain: inout [UInt32], _ schedule: inout [UInt32],
                                 _ input: [UInt8], _ offset: Int) {
        for i in 0..<16 {
            let p = offset + i * 4
            schedule[i] = (UInt32(input[p]) << 24)
                | (UInt32(input[p + 1]) << 16)
                | (UInt32(input[p + 2]) << 8)
                | UInt32(input[p + 3])
        }
        for i in 16..<64 {
            let x = schedule[i - 15]
            let y = schedule[i - 2]
            let sigma0 = rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3)
            let sigma1 = rotateRight(y, 17) ^ rotateRight(y, 19) ^ (y >> 10)
            schedule[i] = schedule[i - 16] &+ sigma0 &+ schedule[i - 7] &+ sigma1
        }

        var a = chain[0]
        var b = chain[1]
        var c = chain[2]
        var d = chain[3]
        var e = chain[4]
        var f = chain[5]
        var g = chain[6]
        var h = chain[7]
        for i in 0..<64 {
            let sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
            let choose = (e & f) ^ (~e & g)
            let t1 = h &+ sum1 &+ choose &+ constants[i] &+ schedule[i]
            let sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
            let majority = (a & b) ^ (a & c) ^ (b & c)
            let t2 = sum0 &+ majority
            h = g
            g = f
            f = e
            e = d &+ t1
            d = c
            c = b
            b = a
            a = t1 &+ t2
        }
        chain[0] &+= a
        chain[1] &+= b
        chain[2] &+= c
        chain[3] &+= d
        chain[4] &+= e
        chain[5] &+= f
        chain[6] &+= g
        chain[7] &+= h
    }
}

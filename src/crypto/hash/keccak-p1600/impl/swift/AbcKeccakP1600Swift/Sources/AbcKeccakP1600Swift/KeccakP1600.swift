public enum KeccakError: Error, Equatable {
    case invalidStateLength
    case invalidOutputLength
}

public enum KeccakP1600 {
    public static let laneCount = 25

    private static let roundConstants: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    private static let moves: [(destination: Int, rotation: Int)] = {
        var x = 1
        var y = 0
        return (0..<24).map { step in
            (x, y) = (y, (2 * x + 3 * y) % 5)
            return (x + 5 * y, (step + 1) * (step + 2) / 2 % 64)
        }
    }()

    /// Applies Keccak-p[1600,24] to 25 lanes in x + 5*y order.
    public static func permute(_ state: inout [UInt64]) throws {
        guard state.count == laneCount else { throw KeccakError.invalidStateLength }
        apply(&state)
    }

    private static func rotate(_ word: UInt64, by distance: Int) -> UInt64 {
        (word << distance) | (word >> (64 - distance))
    }

    fileprivate static func apply(_ state: inout [UInt64]) {
        var parity = [UInt64](repeating: 0, count: 5)
        for constant in roundConstants {
            for x in 0..<5 {
                parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            }
            for x in 0..<5 {
                let delta = parity[(x + 4) % 5] ^ rotate(parity[(x + 1) % 5], by: 1)
                for lane in stride(from: x, to: laneCount, by: 5) {
                    state[lane] ^= delta
                }
            }

            var carried = state[1]
            for move in moves {
                let saved = state[move.destination]
                state[move.destination] = rotate(carried, by: move.rotation)
                carried = saved
            }

            for row in stride(from: 0, to: laneCount, by: 5) {
                let a = state[row], b = state[row + 1], c = state[row + 2]
                let d = state[row + 3], e = state[row + 4]
                state[row] = a ^ (~b & c)
                state[row + 1] = b ^ (~c & d)
                state[row + 2] = c ^ (~d & e)
                state[row + 3] = d ^ (~e & a)
                state[row + 4] = e ^ (~a & b)
            }
            state[0] ^= constant
        }
    }
}

public enum SpongeDomain: UInt8, Sendable {
    case sha3 = 0x06
    case shake = 0x1f
}

/// A byte-oriented Keccak sponge with a 136-byte rate.
public struct Sponge136: Sendable {
    public static let rate = 136
    private var lanes = [UInt64](repeating: 0, count: KeccakP1600.laneCount)
    private var offset = 0

    public init() {}

    public mutating func absorb(_ input: [UInt8]) {
        var start = 0
        if offset != 0 {
            let count = min(input.count, Self.rate - offset)
            for i in 0..<count {
                xor(input[i], at: offset + i)
            }
            offset += count
            guard offset == Self.rate else { return }
            KeccakP1600.apply(&lanes)
            start = count
        }
        while input.count - start >= Self.rate {
            for lane in 0..<(Self.rate / 8) {
                let base = start + lane * 8
                var word: UInt64 = 0
                for byte in 0..<8 {
                    word |= UInt64(input[base + byte]) << (8 * byte)
                }
                lanes[lane] ^= word
            }
            KeccakP1600.apply(&lanes)
            start += Self.rate
        }
        offset = input.count - start
        for i in 0..<offset {
            xor(input[start + i], at: i)
        }
    }

    public func finish(_ domain: SpongeDomain) -> SpongeReader {
        var snapshot = self
        snapshot.xor(domain.rawValue, at: offset)
        snapshot.xor(0x80, at: Self.rate - 1)
        KeccakP1600.apply(&snapshot.lanes)
        return SpongeReader(lanes: snapshot.lanes)
    }

    public mutating func reset() { self = Self() }

    private mutating func xor(_ byte: UInt8, at index: Int) {
        lanes[index / 8] ^= UInt64(byte) << (8 * (index % 8))
    }
}

/// A value-semantic reader over the finalized sponge.
public struct SpongeReader: Sendable {
    private var lanes: [UInt64]
    private var offset = 0

    fileprivate init(lanes: [UInt64]) { self.lanes = lanes }

    public mutating func read(into output: inout [UInt8]) {
        for i in output.indices {
            if offset == Sponge136.rate {
                KeccakP1600.apply(&lanes)
                offset = 0
            }
            output[i] = UInt8(truncatingIfNeeded: lanes[offset / 8] >> (8 * (offset % 8)))
            offset += 1
        }
    }

    public mutating func read(_ count: Int) throws -> [UInt8] {
        guard count >= 0 else { throw KeccakError.invalidOutputLength }
        var output = [UInt8](repeating: 0, count: count)
        read(into: &output)
        return output
    }
}

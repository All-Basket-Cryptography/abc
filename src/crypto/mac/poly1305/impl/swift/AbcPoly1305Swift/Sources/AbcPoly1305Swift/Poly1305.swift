public enum Poly1305Error: Error, Equatable {
    case invalidKey
    case closed
}

public final class Poly1305 {
    public static let keyBytes = 32
    public static let tagBytes = 16
    private static let limbBits = 26
    private static let mask: UInt64 = (1 << limbBits) - 1

    private var residue = [UInt64](repeating: 0, count: 5)
    private var r = [UInt64](repeating: 0, count: 5)
    private var fold = [UInt64](repeating: 0, count: 5)
    private var pad = [UInt64](repeating: 0, count: 4)
    private var tail = [UInt8](repeating: 0, count: 16)
    private var used = 0
    private var closed = false

    public init(key: [UInt8]) throws {
        guard key.count == Self.keyBytes else { throw Poly1305Error.invalidKey }
        var clamped = Array(key.prefix(Self.tagBytes))
        for i in 0..<4 {
            pad[i] = Self.load(key[...], Self.tagBytes + 4 * i)
            clamped[4 * i + 3] &= 15
        }
        for i in [4, 8, 12] { clamped[i] &= 252 }
        r = Self.decode(clamped[...])
        for i in 1..<5 { fold[i] = 5 * r[i] }
    }

    public static func authenticate(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        let state = try Poly1305(key: key)
        try state.update(message)
        return try state.finish()
    }

    public func update(_ bytes: [UInt8]) throws {
        try update(bytes[...])
    }

    public func update(_ bytes: ArraySlice<UInt8>) throws {
        guard !closed else { throw Poly1305Error.closed }
        var next = bytes.startIndex
        if used != 0 {
            let count = min(Self.tagBytes - used, bytes.endIndex - next)
            for i in 0..<count { tail[used + i] = bytes[next + i] }
            used += count
            next += count
            if used < Self.tagBytes { return }
            absorb(tail[...], marker: 1 << 24)
        }
        while bytes.endIndex - next >= Self.tagBytes {
            absorb(bytes[next..<(next + Self.tagBytes)], marker: 1 << 24)
            next += Self.tagBytes
        }
        used = bytes.endIndex - next
        for i in 0..<used { tail[i] = bytes[next + i] }
    }

    public func finish() throws -> [UInt8] {
        guard !closed else { throw Poly1305Error.closed }
        if used != 0 {
            for i in used..<Self.tagBytes { tail[i] = 0 }
            tail[used] = 1
            absorb(tail[...], marker: 0)
        }

        Self.carry(&residue)
        var reduced = residue
        reduced[0] += 5
        for i in 0..<4 {
            reduced[i + 1] += reduced[i] >> Self.limbBits
            reduced[i] &= Self.mask
        }
        let select: UInt64 = 0 &- (reduced[4] >> Self.limbBits)
        reduced[4] &= Self.mask
        for i in 0..<5 { residue[i] ^= (residue[i] ^ reduced[i]) & select }

        let words = [
            residue[0] | (residue[1] << 26),
            (residue[1] >> 6) | (residue[2] << 20),
            (residue[2] >> 12) | (residue[3] << 14),
            (residue[3] >> 18) | (residue[4] << 8),
        ]
        var tag = [UInt8](repeating: 0, count: Self.tagBytes)
        var extra: UInt64 = 0
        for i in 0..<4 {
            let sum = (words[i] & 0xffff_ffff) + pad[i] + extra
            for j in 0..<4 { tag[4 * i + j] = UInt8(truncatingIfNeeded: sum >> (8 * j)) }
            extra = sum >> 32
        }
        close()
        return tag
    }

    public func close() {
        closed = true
        used = 0
        for i in residue.indices {
            residue[i] = 0
            r[i] = 0
            fold[i] = 0
        }
        for i in pad.indices { pad[i] = 0 }
        for i in tail.indices { tail[i] = 0 }
    }

    private static func load(_ bytes: ArraySlice<UInt8>, _ offset: Int) -> UInt64 {
        var word: UInt64 = 0
        for i in 0..<4 { word |= UInt64(bytes[offset + i]) << (8 * i) }
        return word
    }

    private static func decode(_ block: ArraySlice<UInt8>) -> [UInt64] {
        let start = block.startIndex
        let t0 = load(block, start)
        let t1 = load(block, start + 4)
        let t2 = load(block, start + 8)
        let t3 = load(block, start + 12)
        return [
            t0 & mask,
            ((t0 >> 26) | (t1 << 6)) & mask,
            ((t1 >> 20) | (t2 << 12)) & mask,
            ((t2 >> 14) | (t3 << 18)) & mask,
            t3 >> 8,
        ]
    }

    private func absorb(_ block: ArraySlice<UInt8>, marker: UInt64) {
        var h = Self.decode(block)
        for i in 0..<5 { h[i] += residue[i] }
        h[4] += marker
        // Fold product terms using (2^26)^5 = 5 modulo the Poly1305 prime.
        residue[0] = h[0]*r[0] + h[1]*fold[4] + h[2]*fold[3] + h[3]*fold[2] + h[4]*fold[1]
        residue[1] = h[0]*r[1] + h[1]*r[0] + h[2]*fold[4] + h[3]*fold[3] + h[4]*fold[2]
        residue[2] = h[0]*r[2] + h[1]*r[1] + h[2]*r[0] + h[3]*fold[4] + h[4]*fold[3]
        residue[3] = h[0]*r[3] + h[1]*r[2] + h[2]*r[1] + h[3]*r[0] + h[4]*fold[4]
        residue[4] = h[0]*r[4] + h[1]*r[3] + h[2]*r[2] + h[3]*r[1] + h[4]*r[0]
        Self.carry(&residue)
    }

    private static func carry(_ h: inout [UInt64]) {
        for i in 0..<4 {
            h[i + 1] += h[i] >> limbBits
            h[i] &= mask
        }
        h[0] += (h[4] >> limbBits) * 5
        h[4] &= mask
        h[1] += h[0] >> limbBits
        h[0] &= mask
    }
}

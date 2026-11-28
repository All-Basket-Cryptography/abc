public enum Blake2bError: Error, Equatable {
    case invalidDigestSize
    case messageTooLong
}

struct ByteCounter: Equatable, Sendable {
    var low: UInt64 = 0
    var high: UInt64 = 0

    func adding(_ bytes: UInt64) -> Self? {
        let (sum, carry) = low.addingReportingOverflow(bytes)
        let (upper, overflow) = high.addingReportingOverflow(carry ? 1 : 0)
        return overflow ? nil : Self(low: sum, high: upper)
    }
}

/// A byte-oriented, sequential unkeyed BLAKE2b stream.
public struct Blake2b: Sendable {
    public static let blockSize = 128
    public static let maxDigestSize = 64

    private static let iv: SIMD8<UInt64> = SIMD8(
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    )
    private static let sigma: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ]

    public let digestSize: Int
    private var state = Blake2b.iv
    private var pending: [UInt8] = []
    private var compressed = ByteCounter()

    public init(digestSize: Int = maxDigestSize) throws {
        guard (1...Self.maxDigestSize).contains(digestSize) else {
            throw Blake2bError.invalidDigestSize
        }
        self.digestSize = digestSize
        reset()
    }

    /// Reset the stream and keep the selected output length.
    public mutating func reset() {
        state = Self.iv
        state[0] ^= 0x01010000 | UInt64(digestSize)
        pending.removeAll(keepingCapacity: true)
        compressed = ByteCounter()
    }

    public mutating func update(_ input: [UInt8]) throws {
        try update(input[...])
    }

    public mutating func update(_ input: ArraySlice<UInt8>) throws {
        guard compressed.adding(UInt64(pending.count))?.adding(UInt64(input.count)) != nil else {
            throw Blake2bError.messageTooLong
        }
        if input.isEmpty { return }

        let available = Self.blockSize - pending.count
        if input.count <= available {
            pending.append(contentsOf: input)
            return
        }

        var remaining = input
        if !pending.isEmpty {
            pending.append(contentsOf: remaining.prefix(available))
            compressed = advanceBlock(compressed)
            Self.compress(&state, pending[...], count: compressed, final: false)
            pending.removeAll(keepingCapacity: true)
            remaining = remaining.dropFirst(available)
        }
        while remaining.count > Self.blockSize {
            compressed = advanceBlock(compressed)
            Self.compress(&state, remaining.prefix(Self.blockSize), count: compressed, final: false)
            remaining = remaining.dropFirst(Self.blockSize)
        }
        pending.append(contentsOf: remaining)
    }

    /// Return the current digest without consuming or changing the stream.
    public func digest() -> [UInt8] {
        var snapshot = state
        var block = pending
        block.append(contentsOf: repeatElement(0, count: Self.blockSize - block.count))
        // Public updates validate the total, so the last count always fits.
        let count = compressed.adding(UInt64(pending.count))!
        Self.compress(&snapshot, block[...], count: count, final: true)
        return (0..<digestSize).map { UInt8(truncatingIfNeeded: snapshot[$0 / 8] >> (8 * ($0 % 8))) }
    }

    public static func hash(_ input: [UInt8], digestSize: Int = maxDigestSize) throws -> [UInt8] {
        var hasher = try Self(digestSize: digestSize)
        try hasher.update(input)
        return hasher.digest()
    }

    private func advanceBlock(_ count: ByteCounter) -> ByteCounter {
        // The update preflight validates the sum including every nonfinal block.
        count.adding(UInt64(Self.blockSize))!
    }

    private static func compress(
        _ state: inout SIMD8<UInt64>, _ block: ArraySlice<UInt8>, count: ByteCounter, final: Bool
    ) {
        var message = SIMD16<UInt64>(repeating: 0)
        block.withUnsafeBufferPointer { buffer in
            let bytes = UnsafeRawBufferPointer(buffer)
            for i in 0..<16 {
                message[i] = UInt64(littleEndian: bytes.loadUnaligned(fromByteOffset: 8 * i, as: UInt64.self))
            }
        }
        var v = SIMD16<UInt64>(
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
            iv[0], iv[1], iv[2], iv[3], iv[4] ^ count.low, iv[5] ^ count.high, final ? ~iv[6] : iv[6], iv[7]
        )
        for round in 0..<12 {
            let s = 16 * (round % 10)
            mix(&v, 0, 4, 8, 12, message[sigma[s]], message[sigma[s + 1]])
            mix(&v, 1, 5, 9, 13, message[sigma[s + 2]], message[sigma[s + 3]])
            mix(&v, 2, 6, 10, 14, message[sigma[s + 4]], message[sigma[s + 5]])
            mix(&v, 3, 7, 11, 15, message[sigma[s + 6]], message[sigma[s + 7]])
            mix(&v, 0, 5, 10, 15, message[sigma[s + 8]], message[sigma[s + 9]])
            mix(&v, 1, 6, 11, 12, message[sigma[s + 10]], message[sigma[s + 11]])
            mix(&v, 2, 7, 8, 13, message[sigma[s + 12]], message[sigma[s + 13]])
            mix(&v, 3, 4, 9, 14, message[sigma[s + 14]], message[sigma[s + 15]])
        }
        for i in 0..<8 {
            state[i] ^= v[i] ^ v[i + 8]
        }
    }

    @inline(__always)
    private static func mix(_ v: inout SIMD16<UInt64>, _ ai: Int, _ bi: Int, _ ci: Int, _ di: Int,
                            _ x: UInt64, _ y: UInt64) {
        var a = v[ai], b = v[bi], c = v[ci], d = v[di]
        a = a &+ b &+ x
        d = rotate(d ^ a, 32)
        c = c &+ d
        b = rotate(b ^ c, 24)
        a = a &+ b &+ y
        d = rotate(d ^ a, 16)
        c = c &+ d
        b = rotate(b ^ c, 63)
        v[ai] = a
        v[bi] = b
        v[ci] = c
        v[di] = d
    }

    @inline(__always)
    private static func rotate(_ word: UInt64, _ distance: Int) -> UInt64 {
        (word >> distance) | (word << (64 - distance))
    }
}

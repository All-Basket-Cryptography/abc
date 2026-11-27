private let blockSize = 128
private let lengthStart = 112
private let initial: [UInt64] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]
private let constants: [UInt64] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

public enum Sha512Error: Error {
    case messageTooLong
}

/// Byte-oriented FIPS 180-4 SHA-512.
public struct Sha512 {
    private var state = initial
    private var tail = [UInt8](repeating: 0, count: blockSize)
    private var schedule = [UInt64](repeating: 0, count: 16)
    private var used = 0
    private var bytesHigh: UInt64 = 0
    private var bytesLow: UInt64 = 0

    public init() {}

    public mutating func reset() {
        state = initial
        used = 0
        bytesHigh = 0
        bytesLow = 0
    }

    /// Append bytes. Length rejection preserves the stream.
    public mutating func update(_ input: [UInt8]) throws {
        let (low, carry) = bytesLow.addingReportingOverflow(UInt64(input.count))
        let high = bytesHigh + (carry ? 1 : 0)
        guard high < (UInt64(1) << 61) else { throw Sha512Error.messageTooLong }
        bytesHigh = high
        bytesLow = low

        var offset = 0
        if used > 0 {
            offset = min(blockSize - used, input.count)
            for i in 0..<offset { tail[used + i] = input[i] }
            used += offset
            if used < blockSize { return }
            compress(&state, tail, 0, &schedule)
        }
        while input.count - offset >= blockSize {
            compress(&state, input, offset, &schedule)
            offset += blockSize
        }
        used = input.count - offset
        for i in 0..<used { tail[i] = input[offset + i] }
    }

    /// Return an owned digest without closing the stream.
    public func digest() -> [UInt8] {
        var words = state
        var block = [UInt8](repeating: 0, count: used < lengthStart ? blockSize : 2 * blockSize)
        for i in 0..<used { block[i] = tail[i] }
        block[used] = 0x80
        let lengthOffset = block.count - 16
        store(&block, lengthOffset, (bytesHigh << 3) | (bytesLow >> 61))
        store(&block, lengthOffset + 8, bytesLow << 3)
        var scratch = [UInt64](repeating: 0, count: 16)
        for offset in stride(from: 0, to: block.count, by: blockSize) {
            compress(&words, block, offset, &scratch)
        }
        var output = [UInt8](repeating: 0, count: 64)
        for i in words.indices { store(&output, i * 8, words[i]) }
        return output
    }

    public static func hash(_ input: [UInt8]) throws -> [UInt8] {
        var stream = Self()
        try stream.update(input)
        return stream.digest()
    }
}

private func store(_ output: inout [UInt8], _ offset: Int, _ word: UInt64) {
    for j in 0..<8 { output[offset + j] = UInt8(truncatingIfNeeded: word >> (56 - 8 * j)) }
}

private func rotate(_ word: UInt64, _ count: Int) -> UInt64 {
    (word >> count) | (word << (64 - count))
}

private func compress(_ state: inout [UInt64], _ input: [UInt8], _ offset: Int, _ schedule: inout [UInt64]) {
    for i in 0..<16 {
        var word: UInt64 = 0
        for j in 0..<8 { word = (word << 8) | UInt64(input[offset + i * 8 + j]) }
        schedule[i] = word
    }
    var a = state[0], b = state[1], c = state[2], d = state[3]
    var e = state[4], f = state[5], g = state[6], h = state[7]
    for i in constants.indices {
        let slot = i & 15
        if i >= 16 {
            let x = schedule[(i - 15) & 15]
            let y = schedule[(i - 2) & 15]
            let lower0 = rotate(x, 1) ^ rotate(x, 8) ^ (x >> 7)
            let lower1 = rotate(y, 19) ^ rotate(y, 61) ^ (y >> 6)
            schedule[slot] = schedule[slot] &+ lower0 &+ schedule[(i - 7) & 15] &+ lower1
        }
        let upper1 = rotate(e, 14) ^ rotate(e, 18) ^ rotate(e, 41)
        let choose = g ^ (e & (f ^ g))
        let first = h &+ upper1 &+ choose &+ constants[i] &+ schedule[slot]
        let upper0 = rotate(a, 28) ^ rotate(a, 34) ^ rotate(a, 39)
        let majority = (a & b) | (c & (a | b))
        let second = upper0 &+ majority
        h = g
        g = f
        f = e
        e = d &+ first
        d = c
        c = b
        b = a
        a = first &+ second
    }
    state[0] &+= a
    state[1] &+= b
    state[2] &+= c
    state[3] &+= d
    state[4] &+= e
    state[5] &+= f
    state[6] &+= g
    state[7] &+= h
}

import AbcSha256Swift

/// Streaming RFC 2104 HMAC with the independent Swift SHA-256 core.
public struct HmacSha256 {
    private static let blockBytes = 64
    public static let tagBytes = Sha256.digestBytes
    public static let maxMessageBytes = Sha256.maxMessageBytes - UInt64(HmacSha256.blockBytes)

    private var inner: Sha256
    private let outer: Sha256

    public init(key: [UInt8]) throws {
        let normalized: [UInt8]
        if key.count > Self.blockBytes {
            normalized = try Sha256.hash(key)
        } else {
            normalized = key
        }
        var innerPad = [UInt8](repeating: 0x36, count: Self.blockBytes)
        var outerPad = [UInt8](repeating: 0x5c, count: Self.blockBytes)
        for index in normalized.indices {
            innerPad[index] ^= normalized[index]
            outerPad[index] ^= normalized[index]
        }
        var inner = Sha256()
        var outer = Sha256()
        try inner.update(innerPad)
        try outer.update(outerPad)
        self.inner = inner
        self.outer = outer
    }

    public static func authenticate(key: [UInt8], input: [UInt8]) throws -> [UInt8] {
        var stream = try HmacSha256(key: key)
        try stream.update(input)
        return try stream.tag()
    }

    public mutating func update(_ input: [UInt8]) throws {
        try inner.update(input)
    }

    /// Rejected input leaves the message state unchanged.
    public mutating func update(_ input: [UInt8], offset: Int, length: Int) throws {
        try inner.update(input, offset: offset, length: length)
    }

    /// Return an owned tag snapshot and permit later updates.
    public func tag() throws -> [UInt8] {
        var final = outer
        try final.update(inner.digest())
        return final.digest()
    }
}

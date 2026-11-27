import AbcHmacSha256Swift

/// RFC 8018 PBKDF2 using the native Swift HMAC-SHA-256 core.
public enum Pbkdf2Sha256 {
    public enum InputError: Error, Equatable {
        case iterations
        case outputLength
        case saltTooLong
    }

    public static let maxOutputBytes = UInt64(UInt32.max) * UInt64(HmacSha256.tagBytes)

    public static func derive(password: [UInt8], salt: [UInt8], iterations: UInt32,
                              length: Int) throws -> [UInt8] {
        guard iterations != 0 else { throw InputError.iterations }
        guard length > 0, UInt64(length) <= maxOutputBytes else { throw InputError.outputLength }
        guard UInt64(salt.count) <= HmacSha256.maxMessageBytes - 4 else { throw InputError.saltTooLong }
        let tagBytes = HmacSha256.tagBytes
        let blockCount = (length - 1) / tagBytes + 1
        let keyed = try HmacSha256(key: password)
        var output: [UInt8] = []
        output.reserveCapacity(length)
        for index in 1...blockCount {
            let value = try block(keyed, salt: salt, index: UInt32(index), iterations: iterations)
            output.append(contentsOf: value.prefix(length - output.count))
        }
        return output
    }

    private static func block(_ keyed: HmacSha256, salt: [UInt8], index: UInt32,
                              iterations: UInt32) throws -> [UInt8] {
        let counter = [UInt8(truncatingIfNeeded: index >> 24), UInt8(truncatingIfNeeded: index >> 16),
                       UInt8(truncatingIfNeeded: index >> 8), UInt8(truncatingIfNeeded: index)]
        var first = keyed
        try first.update(salt)
        try first.update(counter)
        var term = try first.tag()
        var accumulated = term
        for _ in 1..<iterations {
            var next = keyed
            try next.update(term)
            term = try next.tag()
            for position in accumulated.indices {
                accumulated[position] ^= term[position]
            }
        }
        return accumulated
    }
}

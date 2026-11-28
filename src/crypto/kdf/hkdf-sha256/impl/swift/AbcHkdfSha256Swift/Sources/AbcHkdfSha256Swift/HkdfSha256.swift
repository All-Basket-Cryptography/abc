import AbcHmacSha256Swift

/// RFC 5869 extraction and expansion using the native Swift HMAC core.
public enum HkdfSha256 {
    public enum InputError: Error, Equatable {
        case shortPrk
        case outputLength
        case infoTooLong
    }

    public static let maxOutputBytes = 255 * HmacSha256.tagBytes

    public static func extract(salt: [UInt8]? = nil, inputKeyMaterial: [UInt8]) throws -> [UInt8] {
        let key = salt ?? [UInt8](repeating: 0, count: HmacSha256.tagBytes)
        return try HmacSha256.authenticate(key: key, input: inputKeyMaterial)
    }

    public static func expand(prk: [UInt8], info: [UInt8], length: Int) throws -> [UInt8] {
        let tagBytes = HmacSha256.tagBytes
        guard prk.count >= tagBytes else { throw InputError.shortPrk }
        guard (0...maxOutputBytes).contains(length) else { throw InputError.outputLength }
        guard length != 0 else { return [] }
        let blockCount = (length + tagBytes - 1) / tagBytes
        let extraBytes = blockCount > 1 ? tagBytes + 1 : 1
        guard UInt64(info.count) <= HmacSha256.maxMessageBytes - UInt64(extraBytes) else {
            throw InputError.infoTooLong
        }

        let keyed = try HmacSha256(key: prk)
        var previous: [UInt8] = []
        var output: [UInt8] = []
        output.reserveCapacity(length)
        for index in 1...blockCount {
            var mac = keyed
            try mac.update(previous)
            try mac.update(info)
            try mac.update([UInt8(index)])
            previous = try mac.tag()
            output.append(contentsOf: previous.prefix(length - output.count))
        }
        return output
    }

    public static func derive(salt: [UInt8]? = nil, inputKeyMaterial: [UInt8],
                              info: [UInt8], length: Int) throws -> [UInt8] {
        let prk = try extract(salt: salt, inputKeyMaterial: inputKeyMaterial)
        return try expand(prk: prk, info: info, length: length)
    }
}

import AbcChaCha20Swift
import AbcPoly1305Swift

public enum ChaCha20Poly1305 {
    public static let keyBytes = ChaCha20.keyBytes
    public static let nonceBytes = ChaCha20.nonceBytes
    public static let tagBytes = Poly1305.tagBytes
    private static let zeros = [UInt8](repeating: 0, count: 16)

    public struct SealedMessage: Equatable {
        public let ciphertext: [UInt8]
        public let tag: [UInt8]
    }

    public static func seal(key: [UInt8], nonce: [UInt8], aad: [UInt8],
                            plaintext: [UInt8]) throws -> SealedMessage {
        try validate(key, nonce, plaintext.count)
        let ciphertext = try ChaCha20.xor(key: key, nonce: nonce, counter: 1, input: plaintext)
        return SealedMessage(ciphertext: ciphertext, tag: try authenticate(key, nonce, aad, ciphertext))
    }

    public static func open(key: [UInt8], nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8],
                            tag: [UInt8]) throws -> [UInt8]? {
        try validate(key, nonce, ciphertext.count)
        guard tag.count == tagBytes else { return nil }

        // The authenticated ciphertext remains one Swift array value through verification and decryption.
        let expected = try authenticate(key, nonce, aad, ciphertext)
        var difference: UInt8 = 0
        for i in 0..<tagBytes { difference |= expected[i] ^ tag[i] }
        guard difference == 0 else { return nil }
        return try ChaCha20.xor(key: key, nonce: nonce, counter: 1, input: ciphertext)
    }

    public static func openInto(key: [UInt8], nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8],
                                tag: [UInt8], output: inout [UInt8]) throws -> Bool {
        guard output.count >= ciphertext.count else { throw ChaCha20Error.destinationTooShort }
        guard let verified = try open(key: key, nonce: nonce, aad: aad, ciphertext: ciphertext, tag: tag) else {
            return false
        }
        for i in verified.indices { output[i] = verified[i] }
        return true
    }

    private static func validate(_ key: [UInt8], _ nonce: [UInt8], _ size: Int) throws {
        guard key.count == keyBytes else { throw ChaCha20Error.invalidKey }
        guard nonce.count == nonceBytes else { throw ChaCha20Error.invalidNonce }
        guard ChaCha20.fitsCounter(UInt64(size), 1) else { throw ChaCha20Error.counterExhausted }
    }

    private static func authenticate(_ key: [UInt8], _ nonce: [UInt8], _ aad: [UInt8],
                                     _ ciphertext: [UInt8]) throws -> [UInt8] {
        let block = try ChaCha20.block(key: key, nonce: nonce, counter: 0)
        let mac = try Poly1305(key: Array(block.prefix(Poly1305.keyBytes)))
        defer { mac.close() }
        try updatePadded(mac, aad)
        try updatePadded(mac, ciphertext)
        var lengths = [UInt8](repeating: 0, count: 16)
        littleEndian(UInt64(aad.count), into: &lengths, startingAt: 0)
        littleEndian(UInt64(ciphertext.count), into: &lengths, startingAt: 8)
        try mac.update(lengths)
        return try mac.finish()
    }

    private static func updatePadded(_ mac: Poly1305, _ input: [UInt8]) throws {
        try mac.update(input)
        try mac.update(zeros.prefix((16 - input.count % 16) % 16))
    }

    private static func littleEndian(_ value: UInt64, into output: inout [UInt8], startingAt start: Int) {
        for i in 0..<8 { output[start + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
}

import CAbcEcdsaP256OpenSSL
import CryptoKit
import Foundation

public enum EcdsaP256Error: Error, Equatable {
    case invalidPrivateScalar
    case providerFailure
}

public enum EcdsaP256Sha256 {
    public static let scalarBytes = 32
    public static let signatureBytes = 64
    public static let publicKeyBytes = 65
    private static let order = Data([
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ])

    public static func publicKey(privateScalar: Data) throws -> Data {
        guard scalarInRange(privateScalar) else { throw EcdsaP256Error.invalidPrivateScalar }
        var output = Data(repeating: 0, count: publicKeyBytes)
        let ok = privateScalar.withUnsafeBytes { scalar in
            output.withUnsafeMutableBytes { (destination: UnsafeMutableRawBufferPointer) in
                abc_p256_public(scalar.bindMemory(to: UInt8.self).baseAddress,
                    destination.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        guard ok == 1 else { throw EcdsaP256Error.providerFailure }
        return output
    }

    public static func sign(privateScalar: Data, message: Data) throws -> Data {
        guard scalarInRange(privateScalar) else { throw EcdsaP256Error.invalidPrivateScalar }
        let digest = Data(SHA256.hash(data: message))
        return try deterministicSignature(privateScalar: privateScalar, digest: digest) { nonce in
            try signatureCandidate(privateScalar: privateScalar, digest: digest, nonce: nonce)
        }
    }

    static func signatureCandidate(privateScalar: Data, digest: Data, nonce: Data) throws -> Data? {
        precondition(privateScalar.count == scalarBytes && digest.count == scalarBytes && nonce.count == scalarBytes)
        var output = Data(repeating: 0, count: signatureBytes)
        let status = privateScalar.withUnsafeBytes { scalar in
            digest.withUnsafeBytes { hashed in
                nonce.withUnsafeBytes { candidate in
                    output.withUnsafeMutableBytes { (destination: UnsafeMutableRawBufferPointer) in
                        abc_p256_sign_candidate(scalar.bindMemory(to: UInt8.self).baseAddress,
                            hashed.bindMemory(to: UInt8.self).baseAddress,
                            candidate.bindMemory(to: UInt8.self).baseAddress,
                            destination.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
            }
        }
        if status == 2 { return nil }
        guard status == 1 else { throw EcdsaP256Error.providerFailure }
        return output
    }

    // RFC 6979 §3.2. A rejected nonce or a zero signature field continues the same state.
    static func deterministicSignature(privateScalar: Data, digest: Data,
                                       attempt: (Data) throws -> Data?) rethrows -> Data {
        var key = Data(repeating: 0, count: scalarBytes)
        var value = Data(repeating: 1, count: scalarBytes)
        let reduced = bitsToOctets(digest)
        for marker in [UInt8(0), 1] {
            key = authenticate(key, value + Data([marker]) + privateScalar + reduced)
            value = authenticate(key, value)
        }
        while true {
            value = authenticate(key, value)
            if scalarInRange(value), let signature = try attempt(value) { return signature }
            key = authenticate(key, value + Data([0]))
            value = authenticate(key, value)
        }
    }

    private static func authenticate(_ key: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    private static func bitsToOctets(_ digest: Data) -> Data {
        let digits = Array(digest)
        var reduced = digits
        var borrow: UInt16 = 0
        for index in digits.indices.reversed() {
            let difference = UInt16(digits[index]) &- UInt16(order[index]) &- borrow
            reduced[index] = UInt8(truncatingIfNeeded: difference)
            borrow = difference >> 15
        }
        return borrow == 0 ? Data(reduced) : digest
    }

    public static func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard (publicKey.count == publicKeyBytes && publicKey.first == 4) ||
              (publicKey.count == 33 && (publicKey.first == 2 || publicKey.first == 3)),
              signature.count == signatureBytes,
              scalarInRange(signature.prefix(32)), scalarInRange(signature.suffix(32)) else { return false }
        return publicKey.withUnsafeBytes { point in
            message.withUnsafeBytes { input in
                signature.withUnsafeBytes { (value: UnsafeRawBufferPointer) in
                    abc_p256_verify(point.bindMemory(to: UInt8.self).baseAddress, point.count,
                        input.bindMemory(to: UInt8.self).baseAddress, input.count,
                        value.bindMemory(to: UInt8.self).baseAddress) == 1
                }
            }
        }
    }

    private static func scalarInRange(_ bytes: Data) -> Bool {
        guard bytes.count == scalarBytes else { return false }
        // Scan the full field before passing the scalar to the provider.
        var nonzero: UInt8 = 0
        var borrow: UInt16 = 0
        for (byte, bound) in zip(bytes.reversed(), order.reversed()) {
            nonzero |= byte
            borrow = (UInt16(byte) &- UInt16(bound) &- borrow) >> 15
        }
        return nonzero != 0 && borrow == 1
    }
}

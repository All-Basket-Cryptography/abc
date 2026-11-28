import CAbcEcdsaP256OpenSSL
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
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
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
        var output = Data(repeating: 0, count: signatureBytes)
        let ok = privateScalar.withUnsafeBytes { scalar in
            message.withUnsafeBytes { input in
                output.withUnsafeMutableBytes { (destination: UnsafeMutableRawBufferPointer) in
                    abc_p256_sign(scalar.bindMemory(to: UInt8.self).baseAddress,
                        input.bindMemory(to: UInt8.self).baseAddress, input.count,
                        destination.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        guard ok == 1 else { throw EcdsaP256Error.providerFailure }
        return output
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

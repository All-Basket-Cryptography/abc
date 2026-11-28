import CAbcMlDsa65OpenSSL
import Foundation

public enum MlDsa65Error: Error, Equatable {
    case invalidSeed
    case invalidContext
    case providerFailure
}

public enum MlDsa65 {
    public static let seedBytes = 32
    public static let publicKeyBytes = 1952
    public static let signatureBytes = 3309
    public static let maxContextBytes = 255

    public static func publicKey(seed: Data) throws -> Data {
        guard seed.count == seedBytes else { throw MlDsa65Error.invalidSeed }
        var result = Data(repeating: 0, count: publicKeyBytes)
        let ok = seed.withUnsafeBytes { input in
            result.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                abc_mldsa_public(input.baseAddress, output.baseAddress)
            }
        }
        guard ok == 1 else { throw MlDsa65Error.providerFailure }
        return result
    }

    public static func sign(seed: Data, message: Data, context: Data = Data()) throws -> Data {
        guard seed.count == seedBytes else { throw MlDsa65Error.invalidSeed }
        guard context.count <= maxContextBytes else { throw MlDsa65Error.invalidContext }
        var signature = Data(repeating: 0, count: signatureBytes)
        let ok = seed.withUnsafeBytes { input in
            message.withUnsafeBytes { payload in
                context.withUnsafeBytes { domain in
                    signature.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                        abc_mldsa_sign(input.baseAddress, payload.baseAddress, payload.count,
                            domain.baseAddress, domain.count, output.baseAddress)
                    }
                }
            }
        }
        guard ok == 1 else { throw MlDsa65Error.providerFailure }
        return signature
    }

    public static func verify(publicKey: Data, message: Data, signature: Data, context: Data = Data()) -> Bool {
        guard publicKey.count == publicKeyBytes, signature.count == signatureBytes,
              context.count <= maxContextBytes else { return false }
        return publicKey.withUnsafeBytes { input in
            message.withUnsafeBytes { payload in
                context.withUnsafeBytes { domain in
                    signature.withUnsafeBytes { (value: UnsafeRawBufferPointer) in
                        abc_mldsa_verify(input.baseAddress, payload.baseAddress, payload.count,
                            domain.baseAddress, domain.count, value.baseAddress) == 1
                    }
                }
            }
        }
    }
}

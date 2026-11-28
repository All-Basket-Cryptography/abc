import CAbcMlKem768OpenSSL
import Foundation

public enum MlKem768Error: Error, Equatable {
    case invalidSeed
    case invalidEncapsulationKey
    case invalidCiphertextLength
    case providerFailure
}

public enum MlKem768 {
    public static let seedBytes = 64
    public static let encapsulationKeyBytes = 1184
    public static let ciphertextBytes = 1088
    public static let sharedSecretBytes = 32

    public struct KeyPair {
        public let seed: Data
        public let encapsulationKey: Data
    }

    public struct Encapsulation {
        public let ciphertext: Data
        public let sharedSecret: Data
    }

    public static func generateKey() throws -> KeyPair {
        var seed = Data(repeating: 0, count: seedBytes)
        let ok = seed.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
            abc_mlkem_random_seed(output.baseAddress)
        }
        guard ok == 1 else { throw MlKem768Error.providerFailure }
        return KeyPair(seed: seed, encapsulationKey: try publicKey(seed: seed))
    }

    public static func publicKey(seed: Data) throws -> Data {
        guard seed.count == seedBytes else { throw MlKem768Error.invalidSeed }
        var result = Data(repeating: 0, count: encapsulationKeyBytes)
        let ok = seed.withUnsafeBytes { input in
            result.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                abc_mlkem_public(input.baseAddress, output.baseAddress)
            }
        }
        guard ok == 1 else { throw MlKem768Error.providerFailure }
        return result
    }

    public static func encapsulate(publicKey: Data) throws -> Encapsulation {
        guard canonical(publicKey) else { throw MlKem768Error.invalidEncapsulationKey }
        var ciphertext = Data(repeating: 0, count: ciphertextBytes)
        var secret = Data(repeating: 0, count: sharedSecretBytes)
        let ok = publicKey.withUnsafeBytes { input in
            ciphertext.withUnsafeMutableBytes { (wire: UnsafeMutableRawBufferPointer) in
                secret.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                    abc_mlkem_encapsulate(input.baseAddress, wire.baseAddress, output.baseAddress)
                }
            }
        }
        guard ok == 1 else { throw MlKem768Error.providerFailure }
        return Encapsulation(ciphertext: ciphertext, sharedSecret: secret)
    }

    public static func decapsulate(seed: Data, ciphertext: Data) throws -> Data {
        guard seed.count == seedBytes else { throw MlKem768Error.invalidSeed }
        guard ciphertext.count == ciphertextBytes else { throw MlKem768Error.invalidCiphertextLength }
        var secret = Data(repeating: 0, count: sharedSecretBytes)
        let ok = seed.withUnsafeBytes { input in
            ciphertext.withUnsafeBytes { wire in
                secret.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
                    abc_mlkem_decapsulate(input.baseAddress, wire.baseAddress, output.baseAddress)
                }
            }
        }
        guard ok == 1 else { throw MlKem768Error.providerFailure }
        return secret
    }

    private static func canonical(_ publicKey: Data) -> Bool {
        guard publicKey.count == encapsulationKeyBytes else { return false }
        // The first three polynomials encode two 12-bit coefficients per three bytes.
        return publicKey.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            for offset in stride(from: 0, to: 1152, by: 3) {
                let first = Int(bytes[offset]) | (Int(bytes[offset + 1] & 0x0f) << 8)
                let second = Int(bytes[offset + 1] >> 4) | (Int(bytes[offset + 2]) << 4)
                if first >= 3329 || second >= 3329 { return false }
            }
            return true
        }
    }
}

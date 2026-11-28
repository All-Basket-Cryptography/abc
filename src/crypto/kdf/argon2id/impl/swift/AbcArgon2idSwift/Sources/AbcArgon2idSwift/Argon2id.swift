import CAbcArgon2idOpenSSL
import Foundation

public enum Argon2idError: Error, Equatable {
    case invalidParameters
    case memoryBudgetExceeded
    case providerFailure
}

public enum Argon2id {
    public static func derive(password: Data, salt: Data, secret: Data = Data(), associatedData: Data = Data(),
                              memoryKiB: UInt32, passes: UInt32, lanes: UInt32, tagBytes: UInt32,
                              memoryLimit: UInt64) throws -> Data {
        let count = UInt64(UInt32.max)
        guard lanes > 0, lanes < 1 << 24, UInt64(memoryKiB) >= 8 * UInt64(lanes), passes > 0,
              salt.count >= 8, tagBytes >= 4,
              [password, salt, secret, associatedData].allSatisfy({ UInt64($0.count) <= count }) else {
            throw Argon2idError.invalidParameters
        }
        // Account conservatively for the requested matrix blocks and the returned tag.
        guard UInt64(memoryKiB) * 1024 + UInt64(tagBytes) <= memoryLimit else {
            throw Argon2idError.memoryBudgetExceeded
        }
        var output = Data(repeating: 0, count: Int(tagBytes))
        let success = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                secret.withUnsafeBytes { secretBytes in
                    associatedData.withUnsafeBytes { aadBytes in
                        output.withUnsafeMutableBytes { (tag: UnsafeMutableRawBufferPointer) in
                            abc_argon2id(passwordBytes.baseAddress, passwordBytes.count, saltBytes.baseAddress,
                                saltBytes.count, secretBytes.baseAddress, secretBytes.count,
                                aadBytes.baseAddress, aadBytes.count, memoryKiB, passes, lanes,
                                tag.bindMemory(to: UInt8.self).baseAddress, tag.count)
                        }
                    }
                }
            }
        }
        guard success == 1 else { throw Argon2idError.providerFailure }
        return output
    }
}

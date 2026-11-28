import CommonCrypto
import Foundation

public enum Aes256Error: Error, Equatable {
    case invalidKeySize
    case invalidBlockSize
    case providerFailure(Int32)
    case unexpectedOutputSize
}

/// A single FIPS 197 block transform using the macOS CommonCrypto provider.
public struct Aes256 {
    public static let keyBytes = 32
    public static let blockBytes = 16
    private let key: Data

    public init(key: Data) throws {
        guard key.count == Self.keyBytes else { throw Aes256Error.invalidKeySize }
        self.key = key
    }

    public func encryptBlock(_ plaintext: Data) throws -> Data {
        try crypt(plaintext, operation: CCOperation(kCCEncrypt))
    }

    public func decryptBlock(_ ciphertext: Data) throws -> Data {
        try crypt(ciphertext, operation: CCOperation(kCCDecrypt))
    }

    private func crypt(_ input: Data, operation: CCOperation) throws -> Data {
        guard input.count == Self.blockBytes else { throw Aes256Error.invalidBlockSize }
        var output = Data(repeating: 0, count: Self.blockBytes)
        var written = 0
        let status = key.withUnsafeBytes { (keyBuffer: UnsafeRawBufferPointer) in
            input.withUnsafeBytes { (inputBuffer: UnsafeRawBufferPointer) in
                output.withUnsafeMutableBytes { (outputBuffer: UnsafeMutableRawBufferPointer) in
                    CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                            keyBuffer.baseAddress, keyBuffer.count, nil,
                            inputBuffer.baseAddress, inputBuffer.count,
                            outputBuffer.baseAddress, outputBuffer.count, &written)
                }
            }
        }
        guard status == kCCSuccess else { throw Aes256Error.providerFailure(status) }
        guard written == Self.blockBytes else { throw Aes256Error.unexpectedOutputSize }
        return output
    }
}

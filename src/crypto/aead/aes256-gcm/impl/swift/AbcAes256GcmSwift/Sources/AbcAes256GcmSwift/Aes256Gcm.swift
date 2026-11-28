import CryptoKit
import Foundation

public enum Aes256GcmError: Error, Equatable {
    case invalidKeySize
    case invalidNonceSize
    case invalidTagSize
    case lengthOutOfRange
    case destinationTooShort
}

/// Detached AES-256-GCM with a 96-bit nonce and a full 128-bit tag.
public struct Aes256Gcm {
    public static let keyBytes = 32
    public static let nonceBytes = 12
    public static let tagBytes = 16
    public static let maxPayloadBytes: UInt64 = (1 << 36) - 32
    public static let maxAadBytes: UInt64 = UInt64.max / 8
    private let key: SymmetricKey

    public struct Sealed: Equatable {
        public let ciphertext: Data
        public let tag: Data
    }

    public init(key: Data) throws {
        guard key.count == Self.keyBytes else { throw Aes256GcmError.invalidKeySize }
        self.key = SymmetricKey(data: key)
    }

    public static func fitsLengths(payloadBytes: UInt64, aadBytes: UInt64) -> Bool {
        payloadBytes <= maxPayloadBytes && aadBytes <= maxAadBytes
    }

    /// Supply a nonce which has never been used for encryption under this key.
    public func seal(nonce: Data, plaintext: Data, authenticating aad: Data = Data()) throws -> Sealed {
        let providerNonce = try validatedNonce(nonce, payload: plaintext.count, aad: aad.count)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: providerNonce, authenticating: aad)
        return Sealed(ciphertext: sealed.ciphertext, tag: sealed.tag)
    }

    /// Returns nil for an authentication failure and throws for invalid API sizes.
    public func open(nonce: Data, ciphertext: Data, tag: Data, authenticating aad: Data = Data()) throws -> Data? {
        guard tag.count == Self.tagBytes else { throw Aes256GcmError.invalidTagSize }
        let providerNonce = try validatedNonce(nonce, payload: ciphertext.count, aad: aad.count)
        let box = try AES.GCM.SealedBox(nonce: providerNonce, ciphertext: ciphertext, tag: tag)
        do {
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch CryptoKitError.authenticationFailure {
            return nil
        }
    }

    /// Commits only authenticated plaintext to the caller's output.
    public func openInto(nonce: Data, ciphertext: Data, tag: Data, authenticating aad: Data = Data(),
                         output: inout Data) throws -> Bool {
        guard output.count >= ciphertext.count else { throw Aes256GcmError.destinationTooShort }
        guard let plaintext = try open(nonce: nonce, ciphertext: ciphertext, tag: tag, authenticating: aad) else {
            return false
        }
        output.replaceSubrange(output.startIndex..<(output.startIndex + plaintext.count), with: plaintext)
        return true
    }

    private func validatedNonce(_ nonce: Data, payload: Int, aad: Int) throws -> AES.GCM.Nonce {
        guard nonce.count == Self.nonceBytes else { throw Aes256GcmError.invalidNonceSize }
        guard Self.fitsLengths(payloadBytes: UInt64(payload), aadBytes: UInt64(aad)) else {
            throw Aes256GcmError.lengthOutOfRange
        }
        return try AES.GCM.Nonce(data: nonce)
    }
}

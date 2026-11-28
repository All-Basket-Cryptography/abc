import CryptoKit
import Foundation

public enum X25519Error: Error, Equatable {
    case invalidPrivateKeySize
    case invalidPeerKeySize
}

public enum X25519 {
    public static let keyBytes = 32
    private static let lowOrder = [
        [UInt8](repeating: 0, count: 32),
        [UInt8(1)] + [UInt8](repeating: 0, count: 31),
        [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
        [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
        [UInt8(0xec)] + [UInt8](repeating: 0xff, count: 30) + [0x7f],
    ]

    public static func publicKey(privateKey: Data) throws -> Data {
        try decodePrivate(privateKey).publicKey.rawRepresentation
    }

    /// Returns nil for a low-order peer or an all-zero agreement result.
    public static func sharedSecret(privateKey: Data, peer: Data) throws -> Data? {
        let local = try decodePrivate(privateKey)
        guard peer.count == keyBytes else { throw X25519Error.invalidPeerKeySize }
        var u = Array(peer)
        // After clearing bit 255, u is at most p+18. A single subtraction suffices.
        u[31] &= 0x7f
        if u[31] == 0x7f && u[0] >= 0xed && u[1..<31].allSatisfy({ $0 == 0xff }) {
            u = [u[0] - 0xed] + [UInt8](repeating: 0, count: 31)
        }
        guard !lowOrder.contains(u) else { return nil }
        let remote = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(u))
        let shared = try local.sharedSecretFromKeyAgreement(with: remote)
        return shared.withUnsafeBytes { bytes -> Data? in
            var combined: UInt8 = 0
            for byte in bytes { combined |= byte }
            return combined == 0 ? nil : Data(bytes)
        }
    }

    private static func decodePrivate(_ key: Data) throws -> Curve25519.KeyAgreement.PrivateKey {
        guard key.count == keyBytes else { throw X25519Error.invalidPrivateKeySize }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: key)
    }
}

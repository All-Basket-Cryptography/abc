import AbcEd25519Swift
import Foundation

func check() throws {
    let fixtures = try rows()
    for row in fixtures {
        ensure(try Ed25519.publicKey(seed: row[0]) == row[2], "OpenSSL public key")
        ensure(try Ed25519.sign(seed: row[0], message: row[1]) == row[3], "OpenSSL deterministic signature")
        ensure(Ed25519.verifyStrict(publicKey: row[2], message: row[1], signature: row[3]), "OpenSSL signature")
    }
    let seed = Data(repeating: 0, count: 32)
    let key = try Ed25519.publicKey(seed: seed)
    let message = Data([1, 0, 2, 31])
    let signature = try Ed25519.sign(seed: seed, message: message)
    ensure(!Ed25519.verifyStrict(publicKey: key, message: Data(), signature: signature), "Changed message")
    for width in [0, 31, 33, 64] {
        let malformed = Data(repeating: 0, count: width)
        rejects(Ed25519Error.invalidSeedSize) { _ = try Ed25519.publicKey(seed: malformed) }
        rejects(Ed25519Error.invalidSeedSize) { _ = try Ed25519.sign(seed: malformed, message: message) }
        ensure(!Ed25519.verifyStrict(publicKey: malformed, message: message, signature: signature), "Public width")
    }
    for width in [0, 63, 65] {
        ensure(!Ed25519.verifyStrict(publicKey: key, message: message, signature: Data(repeating: 0, count: width)),
               "Signature width")
    }
    let limit = decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
    ensure(!Ed25519.verifyStrict(publicKey: key, message: message, signature: signature.prefix(32) + limit),
           "Scalar equal to L")
    ensure(!Ed25519.verifyStrict(publicKey: key, message: message,
                                signature: signature.prefix(32) + Data(repeating: 0xff, count: 32)),
           "Scalar larger than L")
    let small = [
        Data(repeating: 0, count: 32),
        Data([1] + [UInt8](repeating: 0, count: 31)),
        decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        decode("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        decode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    ]
    var rejected: [Data] = []
    for var point in small {
        rejected.append(point)
        point[31] ^= 0x80
        rejected.append(point)
    }
    rejected.append(Data([2] + [UInt8](repeating: 0, count: 31)))
    rejected.append(decode("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
    for point in rejected {
        ensure(!Ed25519.verifyStrict(publicKey: point, message: message, signature: signature), "Invalid A point")
        ensure(!Ed25519.verifyStrict(publicKey: key, message: message, signature: point + signature.suffix(32)),
               "Invalid R point")
    }
    print("openssl_cases=\(fixtures.count)")
    print("rfc_known=3")
    print("invalid_points=\(rejected.count)")
    print("bounds=passed")
}

try check()

import AbcEcdsaP256Swift
import CryptoKit
import Foundation

func check() throws {
    let privateKey = decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    let publicKey = decode("0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
    let sample = decode("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
    let test = decode("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" +
        "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083")
    ensure(try EcdsaP256Sha256.publicKey(privateScalar: privateKey) == publicKey, "RFC public key")
    var compressed = Data([3])
    compressed.append(publicKey.dropFirst().prefix(32))
    for (text, expected) in [("sample", sample), ("test", test)] {
        let message = Data(text.utf8)
        ensure(try EcdsaP256Sha256.sign(privateScalar: privateKey, message: message) == expected,
               "RFC 6979 signature")
        ensure(EcdsaP256Sha256.verify(publicKey: publicKey, message: message, signature: expected), "RFC verify")
        ensure(EcdsaP256Sha256.verify(publicKey: compressed, message: message, signature: expected),
               "Compressed RFC point")
    }
    let order = decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    let message = Data("sample".utf8)
    for key in [Data(), Data(repeating: 0, count: 32), order, Data(repeating: 0xff, count: 32)] {
        rejects(EcdsaP256Error.invalidPrivateScalar) { _ = try EcdsaP256Sha256.publicKey(privateScalar: key) }
        rejects(EcdsaP256Error.invalidPrivateScalar) {
            _ = try EcdsaP256Sha256.sign(privateScalar: key, message: message)
        }
    }
    for signature in [Data(), Data(repeating: 0, count: 64), sample.prefix(32) + order] {
        ensure(!EcdsaP256Sha256.verify(publicKey: publicKey, message: message, signature: signature), "Invalid scalar")
    }
    ensure(!EcdsaP256Sha256.verify(publicKey: publicKey, message: Data(), signature: sample), "Changed message")
    ensure(!EcdsaP256Sha256.verify(publicKey: Data([4]) + Data(repeating: 0, count: 64),
                                  message: message, signature: sample), "Off-curve point")
    for index in 0..<48 {
        let provider = P256.Signing.PrivateKey()
        let payload = Data(repeating: UInt8(index), count: index * 11)
        let key = try EcdsaP256Sha256.publicKey(privateScalar: provider.rawRepresentation)
        ensure(key == provider.publicKey.x963Representation, "Independent public point")
        let signed = try EcdsaP256Sha256.sign(privateScalar: provider.rawRepresentation, message: payload)
        let repeated = try EcdsaP256Sha256.sign(privateScalar: provider.rawRepresentation, message: payload)
        ensure(signed == repeated, "Determinism")
        let providerSignature = try P256.Signing.ECDSASignature(rawRepresentation: signed)
        ensure(provider.publicKey.isValidSignature(providerSignature, for: payload), "CryptoKit accepts OpenSSL")
        let signature = try provider.signature(for: payload).rawRepresentation
        ensure(EcdsaP256Sha256.verify(publicKey: key, message: payload, signature: signature),
               "OpenSSL accepts CryptoKit")
    }
    print("rfc_known=3")
    print("interoperability=48")
    print("bounds=passed")
}

try check()

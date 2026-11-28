import AbcX25519Swift
import Foundation

func check() throws {
    let alice = decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let bob = decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    let alicePublic = decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    let bobPublic = decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    let shared = decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    ensure(try X25519.publicKey(privateKey: alice) == alicePublic, "Alice RFC key")
    ensure(try X25519.publicKey(privateKey: bob) == bobPublic, "Bob RFC key")
    ensure(try X25519.sharedSecret(privateKey: alice, peer: bobPublic) == shared, "Alice RFC secret")
    ensure(try X25519.sharedSecret(privateKey: bob, peer: alicePublic) == shared, "Bob RFC secret")

    var scalar = Data([9] + [UInt8](repeating: 0, count: 31))
    var peer = scalar
    for i in 1...1000 {
        guard let next = try X25519.sharedSecret(privateKey: scalar, peer: peer) else {
            preconditionFailure("RFC ladder iterations")
        }
        peer = scalar
        scalar = next
        if i == 1 {
            ensure(scalar == decode("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
                   "RFC first iteration")
        }
    }
    ensure(scalar == decode("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
           "RFC 1,000th iteration")

    let privateKey = Data(repeating: 0x7c, count: 32)
    let expected = try X25519.publicKey(privateKey: privateKey)
    for bits in 0..<32 {
        var alias = privateKey
        alias[0] = (alias[0] & 0xf8) | UInt8(bits & 7)
        alias[31] = (alias[31] & 0x3f) | UInt8((bits >> 3) << 6)
        ensure(try X25519.publicKey(privateKey: alias) == expected, "Scalar clamp alias")
    }
    var alias = Data(repeating: 0xff, count: 32)
    alias[0] = 0xf6
    ensure(try X25519.sharedSecret(privateKey: privateKey, peer: alias) == expected, "p+9 with high bit")
    alias[31] &= 0x7f
    ensure(try X25519.sharedSecret(privateKey: privateKey, peer: alias) == expected, "p+9 reduction")
    alias = Data([9] + [UInt8](repeating: 0, count: 30) + [0x80])
    ensure(try X25519.sharedSecret(privateKey: privateKey, peer: alias) == expected, "High-bit mask")
    for wire in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        var low = decode(wire)
        ensure(try X25519.sharedSecret(privateKey: privateKey, peer: low) == nil, "Low-order rejection")
        low[31] |= 0x80
        ensure(try X25519.sharedSecret(privateKey: privateKey, peer: low) == nil, "Low-order alias rejection")
    }

    for width in [0, 31, 33, 56] {
        let malformed = Data(repeating: 0, count: width)
        rejects(X25519Error.invalidPrivateKeySize) { _ = try X25519.publicKey(privateKey: malformed) }
        rejects(X25519Error.invalidPrivateKeySize) {
            _ = try X25519.sharedSecret(privateKey: malformed, peer: expected)
        }
        rejects(X25519Error.invalidPeerKeySize) {
            _ = try X25519.sharedSecret(privateKey: privateKey, peer: malformed)
        }
    }
    let fixtures = try rows()
    for row in fixtures {
        ensure(try X25519.publicKey(privateKey: row[0]) == row[2], "OpenSSL public key")
        ensure(try X25519.sharedSecret(privateKey: row[0], peer: row[1]) == row[3], "OpenSSL shared secret")
    }
    print("openssl_cases=\(fixtures.count)")
    print("rfc_known=6")
    print("scalar_aliases=32")
    print("peer_aliases=3")
    print("low_order_rejections=14")
    print("bounds=passed")
}

try check()

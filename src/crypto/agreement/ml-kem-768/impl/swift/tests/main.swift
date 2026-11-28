import AbcMlKem768Swift
import Foundation

func wire(_ bytes: Data) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func check() throws {
    var known = 0
    var reciprocal = 0
    for row in try rows() {
        if row.count == 2 {
            ensure(try MlKem768.publicKey(seed: row[0]) == row[1], "ACVP public key")
            known += 1
            continue
        }
        let seed = row[0], publicKey = row[1], ciphertext = row[2], shared = row[3]
        ensure(try MlKem768.publicKey(seed: seed) == publicKey, "Go public key")
        ensure(try MlKem768.decapsulate(seed: seed, ciphertext: ciphertext) == shared, "Go encapsulation")
        var changed = ciphertext
        changed[0] ^= 1
        ensure(try MlKem768.decapsulate(seed: seed, ciphertext: changed) == row[4], "Exact implicit rejection")
        let result = try MlKem768.encapsulate(publicKey: publicKey)
        ensure(try MlKem768.decapsulate(seed: seed, ciphertext: result.ciphertext) == result.sharedSecret,
               "Provider round trip")
        print("reciprocal=\(wire(seed)):\(wire(result.ciphertext)):\(wire(result.sharedSecret))")
        reciprocal += 1
    }
    let key = try MlKem768.generateKey()
    let result = try MlKem768.encapsulate(publicKey: key.encapsulationKey)
    ensure(try MlKem768.decapsulate(seed: key.seed, ciphertext: result.ciphertext) == result.sharedSecret,
           "Random key round trip")
    rejects(MlKem768Error.invalidSeed) { _ = try MlKem768.publicKey(seed: key.seed.dropLast()) }
    rejects(MlKem768Error.invalidCiphertextLength) {
        _ = try MlKem768.decapsulate(seed: key.seed, ciphertext: result.ciphertext.dropLast())
    }
    rejects(MlKem768Error.invalidEncapsulationKey) {
        _ = try MlKem768.encapsulate(publicKey: key.encapsulationKey.dropLast())
    }
    var noncanonical = key.encapsulationKey
    noncanonical[0] = 0xff
    noncanonical[1] |= 0x0f
    rejects(MlKem768Error.invalidEncapsulationKey) { _ = try MlKem768.encapsulate(publicKey: noncanonical) }
    print("acvp_known=\(known)")
    print("go_cases=\(reciprocal)")
    print("bounds=passed")
}

try check()

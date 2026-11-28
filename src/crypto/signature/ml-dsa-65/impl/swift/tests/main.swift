import AbcMlDsa65Swift
import CryptoKit
import Foundation

func check() throws {
    var known = 0
    var reciprocal = 0
    for row in try rows() {
        if row.count == 2 {
            let publicKey = try MlDsa65.publicKey(seed: row[0])
            ensure(Data(SHA256.hash(data: publicKey)) == row[1], "ACVP key derivation digest")
            known += 1
        } else if row[0].count == 1 {
            let accepted = MlDsa65.verify(publicKey: row[1], message: row[2], signature: row[4], context: row[3])
            ensure(accepted == (row[0].first == 1), "ACVP verification expectation")
            known += 1
        } else {
            let seed = row[0], message = row[1], context = row[2], key = row[3], signature = row[4]
            ensure(try MlDsa65.publicKey(seed: seed) == key, "Go key derivation")
            let signed = try MlDsa65.sign(seed: seed, message: message, context: context)
            ensure(signed == signature, "Go deterministic signature")
            ensure(MlDsa65.verify(publicKey: key, message: message, signature: signature, context: context),
                   "Go signature verification")
            reciprocal += 1
        }
    }
    let seed = Data(repeating: 5, count: 32)
    let key = try MlDsa65.publicKey(seed: seed)
    let context = Data([0, 3, 5])
    let signature = try MlDsa65.sign(seed: seed, message: Data(), context: context)
    ensure(!MlDsa65.verify(publicKey: key, message: Data(), signature: signature, context: Data()), "Wrong context")
    ensure(!MlDsa65.verify(publicKey: key, message: Data([9]), signature: signature, context: context), "Wrong message")
    ensure(!MlDsa65.verify(publicKey: key.dropLast(), message: Data(), signature: signature, context: context),
           "Short public key")
    ensure(!MlDsa65.verify(publicKey: key, message: Data(), signature: signature.dropLast(), context: context),
           "Short signature")
    let long = Data(repeating: 0, count: 256)
    ensure(!MlDsa65.verify(publicKey: key, message: Data(), signature: signature, context: long), "Long context")
    rejects(MlDsa65Error.invalidSeed) { _ = try MlDsa65.publicKey(seed: seed.dropLast()) }
    rejects(MlDsa65Error.invalidContext) { _ = try MlDsa65.sign(seed: seed, message: Data(), context: long) }
    print("acvp_known=\(known)")
    print("go_cases=\(reciprocal)")
    print("bounds=passed")
}

try check()

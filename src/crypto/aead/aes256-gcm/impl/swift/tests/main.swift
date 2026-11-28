import AbcAes256GcmSwift
import CryptoKit
import Dispatch
import Foundation

func check() throws {
    let rows = try fixtures()
    var rejected = 0
    for (index, row) in rows.enumerated() {
        let cipher = try Aes256Gcm(key: row[0])
        let nonce = row[1], aad = row[2], plaintext = row[3], ciphertext = row[4], tag = row[5]
        let sealed = try cipher.seal(nonce: nonce, plaintext: plaintext, authenticating: aad)
        ensure(sealed.ciphertext == ciphertext && sealed.tag == tag, "AES-256-GCM seal")
        ensure(try cipher.open(nonce: nonce, ciphertext: ciphertext, tag: tag, authenticating: aad) == plaintext,
               "AES-256-GCM OpenSSL fixture open")

        if index < 18 {
            let saved = Data(repeating: 0xa9, count: plaintext.count + 7)
            var output = saved
            var wrongTag = tag
            wrongTag[index % tag.count] ^= 1
            ensure(try !cipher.openInto(nonce: nonce, ciphertext: ciphertext, tag: wrongTag,
                                       authenticating: aad, output: &output), "Modified tag accepted")
            rejected += 1
            var inPlace = ciphertext
            ensure(try !cipher.openInto(nonce: nonce, ciphertext: inPlace, tag: wrongTag,
                                       authenticating: aad, output: &inPlace), "In-place modified tag accepted")
            ensure(inPlace == ciphertext, "Failure changed in-place ciphertext")
            rejected += 1
            var wrongNonce = nonce
            wrongNonce[0] ^= 1
            ensure(try !cipher.openInto(nonce: wrongNonce, ciphertext: ciphertext, tag: tag,
                                       authenticating: aad, output: &output), "Modified nonce accepted")
            rejected += 1
            ensure(try !cipher.openInto(nonce: nonce, ciphertext: ciphertext, tag: tag,
                                       authenticating: aad + Data([1]), output: &output), "Modified AAD accepted")
            rejected += 1
            if !ciphertext.isEmpty {
                var wrongBody = ciphertext
                wrongBody[0] ^= 1
                ensure(try !cipher.openInto(nonce: nonce, ciphertext: wrongBody, tag: tag,
                                           authenticating: aad, output: &output), "Modified ciphertext accepted")
                rejected += 1
            }
            ensure(output == saved, "Authentication failure changed destination")
            ensure(try cipher.openInto(nonce: nonce, ciphertext: ciphertext, tag: tag,
                                      authenticating: aad, output: &output), "Valid openInto failed")
            ensure(output.prefix(plaintext.count) == plaintext && output.suffix(7) == saved.suffix(7),
                   "Opening wrote outside the plaintext prefix")
        }
    }

    for size in [0, 16, 24, 31, 33] {
        rejects(Aes256GcmError.invalidKeySize) { _ = try Aes256Gcm(key: Data(repeating: 0, count: size)) }
    }
    let trial = rows[1]
    let cipher = try Aes256Gcm(key: trial[0])
    let nonce = trial[1], ciphertext = trial[4], tag = trial[5]
    var destination = Data(repeating: 0xa9, count: ciphertext.count)
    let saved = destination
    for size in [0, 11, 13, 16] {
        let badNonce = Data(repeating: 0, count: size)
        rejects(Aes256GcmError.invalidNonceSize) {
            _ = try cipher.seal(nonce: badNonce, plaintext: Data())
        }
        rejects(Aes256GcmError.invalidNonceSize) {
            _ = try cipher.openInto(nonce: badNonce, ciphertext: ciphertext, tag: tag, output: &destination)
        }
    }
    for size in [0, 8, 15, 17] {
        rejects(Aes256GcmError.invalidTagSize) {
            _ = try cipher.openInto(nonce: nonce, ciphertext: ciphertext, tag: Data(repeating: 0, count: size),
                                    output: &destination)
        }
    }
    var short = saved.dropLast()
    let savedShort = short
    rejects(Aes256GcmError.destinationTooShort) {
        _ = try cipher.openInto(nonce: nonce, ciphertext: ciphertext, tag: tag, output: &short)
    }
    ensure(destination == saved && short == savedShort, "API preflight changed destination")
    let maxPayload = Aes256Gcm.maxPayloadBytes
    let maxAad = Aes256Gcm.maxAadBytes
    ensure(Aes256Gcm.fitsLengths(payloadBytes: maxPayload, aadBytes: maxAad), "Exact limits")
    ensure(!Aes256Gcm.fitsLengths(payloadBytes: maxPayload + 1, aadBytes: maxAad), "Payload overflow")
    ensure(!Aes256Gcm.fitsLengths(payloadBytes: 0, aadBytes: maxAad + 1), "AAD overflow")
    print("cases=\(rows.count)")
    print("auth_failures=\(rejected)")
    print("bounds=passed")
}

func benchmark() throws {
    let iterations = 1000
    let trials = 7
    let key = Data(repeating: 0, count: 32), nonce = Data(repeating: 0, count: 12)
    let aad = Data(repeating: 0, count: 16), plaintext = Data(repeating: 0, count: 4096)
    let cipher = try Aes256Gcm(key: key)
    let providerKey = SymmetricKey(data: key)
    let providerNonce = try AES.GCM.Nonce(data: nonce)
    let expected = try cipher.seal(nonce: nonce, plaintext: plaintext, authenticating: aad)
    let box = try AES.GCM.SealedBox(nonce: providerNonce, ciphertext: expected.ciphertext, tag: expected.tag)
    func measure(_ work: () throws -> Void) rethrows -> Double {
        for _ in 0..<iterations { try work() }
        var samples: [Double] = []
        for _ in 0..<trials {
            let start = DispatchTime.now().uptimeNanoseconds
            for _ in 0..<iterations { try work() }
            samples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / Double(iterations))
        }
        return samples.sorted()[trials / 2]
    }
    var wrapped = expected, provider = box
    var opening = Data(), providerOpening = Data()
    let seal = try measure { wrapped = try cipher.seal(nonce: nonce, plaintext: plaintext, authenticating: aad) }
    let providerSeal = try measure {
        provider = try AES.GCM.seal(plaintext, using: providerKey, nonce: providerNonce, authenticating: aad)
    }
    let open = try measure {
        opening = try cipher.open(nonce: nonce, ciphertext: expected.ciphertext, tag: expected.tag,
                                  authenticating: aad) ?? Data()
    }
    let providerOpen = try measure { providerOpening = try AES.GCM.open(box, using: providerKey, authenticating: aad) }
    ensure(wrapped == expected && provider.ciphertext == expected.ciphertext && provider.tag == expected.tag,
           "Benchmark seal results")
    ensure(opening == plaintext && providerOpening == plaintext, "Benchmark open results")
    print("seal_ns=\(seal)")
    print("open_ns=\(open)")
    print("provider_seal_ns=\(providerSeal)")
    print("provider_open_ns=\(providerOpen)")
    print("iterations=\(iterations)")
    print("trials=\(trials)")
}

if CommandLine.arguments[1] == "--benchmark" {
    try benchmark()
} else {
    try check()
}

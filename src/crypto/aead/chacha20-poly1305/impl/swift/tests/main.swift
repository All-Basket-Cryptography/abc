import AbcChaCha20Poly1305Swift

func check() throws {
    let key = (128..<160).map { UInt8($0) }
    let nonce = decode("070000004041424344454647")
    let aad = decode("50515253c0c1c2c3c4c5c6c7")
    let sealed = try ChaCha20Poly1305.seal(key: key, nonce: nonce, aad: aad, plaintext: rfcMessage)
    let ciphertext = sealed.ciphertext
    let tag = sealed.tag
    ensure(wire(ciphertext) ==
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
        "3ff4def08e4b7a9de576d26586cec64b6116", "RFC ciphertext")
    ensure(wire(tag) == "1ae10b594f09e26a7e902ecbd0600691", "RFC tag")

    var output = [UInt8](repeating: 0xa9, count: ciphertext.count + 9)
    let saved = output
    func tryOpen(_ data: [UInt8], _ auth: [UInt8], _ associated: [UInt8]) throws -> Bool {
        try ChaCha20Poly1305.openInto(key: key, nonce: nonce, aad: associated,
                                    ciphertext: data, tag: auth, output: &output)
    }
    for i in tag.indices {
        var changed = tag
        changed[i] ^= 1
        ensure(try !tryOpen(ciphertext, changed, aad), "Modified tag")
        var inPlace = ciphertext
        let valid = try ChaCha20Poly1305.openInto(key: key, nonce: nonce, aad: aad,
                                                ciphertext: inPlace, tag: changed, output: &inPlace)
        ensure(!valid && inPlace == ciphertext, "Rejected in-place tag changed data")
    }
    var modified = ciphertext
    modified[0] ^= 1
    ensure(try !tryOpen(modified, tag, aad), "Modified ciphertext")
    ensure(try !tryOpen(ciphertext, tag, []), "Modified AAD")
    ensure(try !tryOpen(ciphertext, Array(tag.dropLast()), aad), "Short tag")
    ensure(try !tryOpen(ciphertext, tag + [0], aad), "Long tag")
    ensure(output == saved, "Authentication failure changed destination")
    rejects("Invalid key size") { _ = try ChaCha20Poly1305.seal(key: [], nonce: nonce, aad: [], plaintext: []) }
    rejects("Invalid nonce size") { _ = try ChaCha20Poly1305.seal(key: key, nonce: [], aad: [], plaintext: []) }
    rejects("Short destination") {
        var short: [UInt8] = []
        _ = try ChaCha20Poly1305.openInto(key: key, nonce: nonce, aad: aad,
                                         ciphertext: ciphertext, tag: tag, output: &short)
    }

    ensure(try tryOpen(ciphertext, tag, aad), "RFC open")
    ensure(Array(output.prefix(ciphertext.count)) == rfcMessage, "RFC plaintext")
    ensure(output.suffix(9) == saved.suffix(9), "Untouched trailing bytes")

    for row in try fixtures() {
        let suiteKey = decode(row[0]), suiteNonce = decode(row[1]), suiteAad = decode(row[2])
        let message = decode(row[3])
        let result = try ChaCha20Poly1305.seal(key: suiteKey, nonce: suiteNonce, aad: suiteAad, plaintext: message)
        ensure(try ChaCha20Poly1305.open(key: suiteKey, nonce: suiteNonce, aad: suiteAad,
                                        ciphertext: result.ciphertext, tag: result.tag) == message,
               "Fixture roundtrip")
        print("result=\(wire(result.ciphertext))\t\(wire(result.tag))")
    }
    print("rfc=1")
    print("boundaries=passed")
}

try check()

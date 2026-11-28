import AbcChaCha20Swift

func check() throws {
    let key = (0..<32).map { UInt8($0) }
    let nonce = decode("000000000000004a00000000")
    let blockNonce = decode("000000090000004a00000000")
    ensure(try wire(ChaCha20.block(key: key, nonce: blockNonce, counter: 1)) ==
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", "RFC block")
    var message = try ChaCha20.xor(key: key, nonce: nonce, counter: 1, input: rfcMessage)
    ensure(wire(message) ==
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
        "5af90bbf74a35be6b40b8eedf2785e42874d", "RFC stream")
    try ChaCha20.xorInto(key: key, nonce: nonce, counter: 1, input: message, output: &message)
    ensure(message == rfcMessage, "In-place stream roundtrip")

    for counter in [UInt32(0), 1, UInt32.max - 1, UInt32.max] {
        let bound = ((1 << 32) - UInt64(counter)) * 64
        ensure(ChaCha20.fitsCounter(0, counter), "Empty payload")
        ensure(ChaCha20.fitsCounter(bound, counter), "Exact bound")
        ensure(!ChaCha20.fitsCounter(bound + 1, counter), "Counter overflow")
    }
    var guarded = [UInt8](repeating: 0xa9, count: 66)
    let saved = guarded
    rejects("Counter overflow") {
        try ChaCha20.xorInto(key: key, nonce: nonce, counter: .max,
                             input: [UInt8](repeating: 0, count: 65), output: &guarded)
    }
    rejects("Short output") {
        try ChaCha20.xorInto(key: key, nonce: nonce, counter: 1, input: rfcMessage, output: &guarded)
    }
    rejects("Bad key length") {
        try ChaCha20.xorInto(key: [], nonce: nonce, counter: 1, input: [0], output: &guarded)
    }
    rejects("Bad nonce length") {
        try ChaCha20.xorInto(key: key, nonce: [], counter: 1, input: [0], output: &guarded)
    }
    ensure(guarded == saved, "Rejected input changed destination")
    try ChaCha20.xorInto(key: key, nonce: nonce, counter: .max,
                         input: [UInt8](repeating: 0, count: 64), output: &guarded)
    ensure(try Array(guarded.prefix(64)) == ChaCha20.block(key: key, nonce: nonce, counter: .max),
           "Final valid counter")
    ensure(guarded.suffix(2) == saved.suffix(2), "Untouched tail")

    for row in try fixtures() {
        let output = try ChaCha20.xor(key: decode(row[0]), nonce: decode(row[1]),
                                     counter: UInt32(row[2])!, input: decode(row[3]))
        print("result=\(wire(output))")
    }
    print("rfc=2")
    print("boundaries=passed")
}

try check()

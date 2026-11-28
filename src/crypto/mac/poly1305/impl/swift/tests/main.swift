import AbcPoly1305Swift

func check() throws {
    for (index, row) in try fixtures().enumerated() {
        let key = decode(row[0])
        let message = decode(row[1])
        let expected = decode(row[2])
        let tag = try Poly1305.authenticate(key: key, message: message)
        ensure(tag == expected, "One-shot Poly1305")
        for split in stride(from: 0, through: message.count, by: index < 8 ? 1 : 16) {
            let mac = try Poly1305(key: key)
            try mac.update(message[..<split])
            try mac.update([UInt8]())
            try mac.update(message[split...])
            ensure(try mac.finish() == expected, "Split Poly1305")
        }
        print("result=\(wire(tag))")
    }
    rejects("Invalid Poly1305 key") { _ = try Poly1305(key: []) }
    let inactive = try Poly1305(key: [UInt8](repeating: 0, count: 32))
    let single: [UInt8] = [0]
    try inactive.update(single)
    ensure(try inactive.finish() == [UInt8](repeating: 0, count: 16), "Zero-key test vector")
    rejects("Closed Poly1305 update") { try inactive.update(single) }
    rejects("Closed Poly1305 finish") { _ = try inactive.finish() }
    print("rfc=8")
    print("boundaries=passed")
}

try check()

import ABCCrypto

let input: [UInt8] = [0x61, 0x62, 0x63]
let expected: [UInt8] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
]

let identifier = try SHA256.implementation()
precondition(identifier == "sha256-abc-rust-portable")
let digest = try SHA256.digest(input)
precondition(digest == expected)

let stream = try SHA256Stream()
try stream.update([0x61])
try stream.update([0x62, 0x63])
let streamed = try stream.finish()
precondition(streamed == expected)
do {
    _ = try stream.finish()
    fatalError("finalization accepted twice")
} catch ABCError.nativeStatus(3) {}
try stream.reset()
try stream.update(input)
let afterReset = try stream.finish()
precondition(afterReset == expected)
stream.close()
stream.close()
do {
    try stream.update(input)
    fatalError("closed stream accepted data")
} catch ABCError.nativeStatus(3) {}

print("Swift SHA-256 external consumer passed")

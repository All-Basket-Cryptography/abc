import AbcHmacSha256Swift
import CryptoKit
import Foundation
import XCTest

private struct TestGenerator {
    private var state: UInt64 = 4231

    mutating func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in
            state = state &* 6364136223846793005 &+ 1
            return UInt8(truncatingIfNeeded: state >> 32)
        }
    }
}

final class HmacSha256Tests: XCTestCase {
    private func reference(_ key: [UInt8], _ input: [UInt8], count: Int? = nil) -> [UInt8] {
        let oracleKey = SymmetricKey(data: Data(key.isEmpty ? [UInt8](repeating: 0, count: 64) : key))
        let tag = HMAC<CryptoKit.SHA256>.authenticationCode(
            for: Data(input.prefix(count ?? input.count)), using: oracleKey
        )
        return Array(tag)
    }

    private func compare(_ key: [UInt8], _ input: [UInt8], _ tag: [UInt8]) throws -> Int {
        XCTAssertEqual(try HmacSha256.authenticate(key: key, input: input), tag)
        var callerKey = key
        var stream = try HmacSha256(key: callerKey)
        for index in callerKey.indices {
            callerKey[index] = 0xa5
        }

        var frame: [UInt8] = [0x5a] + input + [0x5a]
        let middle = input.count / 2
        try stream.update(frame, offset: 1, length: middle)
        let prefix = reference(key, input, count: middle)
        XCTAssertEqual(try stream.tag(), prefix)
        XCTAssertThrowsError(try stream.update(frame, offset: 1, length: Int.max))
        XCTAssertEqual(try stream.tag(), prefix)

        var copy = stream
        try copy.update(frame, offset: middle + 1, length: input.count - middle)
        try copy.update(frame, offset: frame.count, length: 0)
        XCTAssertEqual(try copy.tag(), tag)
        XCTAssertEqual(try stream.tag(), prefix)
        var returned = try copy.tag()
        returned[0] ^= 0xff
        for index in frame.indices {
            frame[index] = 0
        }
        XCTAssertNotEqual(returned, try copy.tag())
        XCTAssertEqual(try copy.tag(), tag)
        return 2
    }

    func testKnownAnswers() throws {
        let vectors: [([UInt8], String, String)] = [
            ([UInt8](repeating: 0x0b, count: 20), "Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (Array("Jefe".utf8), "what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            ([UInt8](repeating: 0xaa, count: 131), "Test Using Larger Than Block-Size Key - Hash Key First",
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        ]
        var snapshots = 0
        for (key, message, expected) in vectors {
            let input = Array(message.utf8)
            let tag = reference(key, input)
            XCTAssertEqual(tag.map { String(format: "%02x", $0) }.joined(), expected)
            snapshots += try compare(key, input, tag)
        }
        print("known_answers=\(vectors.count)")
        print("known_answer_snapshots=\(snapshots)")
    }

    func testProviderBoundariesAndValueState() throws {
        var random = TestGenerator()
        var comparisons = 0
        var snapshots = 0
        for keyLength in [0, 1, 31, 32, 63, 64, 65, 131, 1024] {
            for length in [0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 257, 1024] {
                let key = random.bytes(keyLength)
                let input = random.bytes(length)
                snapshots += try compare(key, input, reference(key, input))
                comparisons += 1
            }
        }
        print("one_shot_comparisons=\(comparisons)")
        print("streaming_snapshots=\(snapshots)")
    }
}

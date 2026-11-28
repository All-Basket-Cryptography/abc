import CryptoKit
import Foundation
import XCTest
@testable import AbcSha256Swift

private struct TestGenerator {
    private var state: UInt64 = 216

    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8(truncatingIfNeeded: next()) }
    }
}

final class Sha256Tests: XCTestCase {
    private func reference(_ input: [UInt8], count: Int? = nil) -> [UInt8] {
        Array(CryptoKit.SHA256.hash(data: Data(input.prefix(count ?? input.count))))
    }

    private func compare(_ input: [UInt8], random: inout TestGenerator) throws -> Int {
        let expected = reference(input)
        XCTAssertEqual(try Sha256.hash(input), expected, "One-shot length \(input.count)")

        let frame: [UInt8] = [0x5a] + input + [0x5a]
        var stream = Sha256()
        try stream.update(frame, offset: 1, length: 0)
        XCTAssertEqual(stream.digest(), reference(input, count: 0))
        let chunkLimit = input.count <= 257 ? 32 : 8192
        var offset = 0
        var snapshots = 1
        while offset < input.count {
            let chunk = Int(random.next() % UInt64(chunkLimit)) + 1
            let count = min(input.count - offset, chunk)
            try stream.update(frame, offset: offset + 1, length: count)
            offset += count
            XCTAssertEqual(stream.digest(), reference(input, count: offset), "Streaming prefix \(offset) of \(input.count)")
            snapshots += 1
        }
        try stream.update(frame, offset: frame.count, length: 0)
        XCTAssertEqual(stream.digest(), expected)
        return snapshots
    }

    func testKnownAnswersAndDifferentialStreams() throws {
        let knownAnswers: [([UInt8], String)] = [
            ([], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (Array("abc".utf8), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (Array(repeating: 0x61, count: 1_000_000),
             "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        ]
        var random = TestGenerator()
        var snapshots = 0
        for (message, encoded) in knownAnswers {
            let actual = try Sha256.hash(message).map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(actual, encoded)
            snapshots += try compare(message, random: &random)
        }
        let boundaryLengths = [0, 1, 7, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121,
                               127, 128, 129, 255, 256, 257, 1024, 4096, 65537, 1048576]
        for length in boundaryLengths {
            let bytes = random.bytes(length)
            snapshots += try compare(bytes, random: &random)
        }
        let randomCases = 128
        for _ in 0..<randomCases {
            let length = Int(random.next() % 8193)
            let bytes = random.bytes(length)
            snapshots += try compare(bytes, random: &random)
        }
        print("known_answers=\(knownAnswers.count)")
        print("one_shot_comparisons=\(knownAnswers.count + boundaryLengths.count + randomCases)")
        print("streaming_snapshots=\(snapshots)")
    }

    func testRangeValidationAndValueState() throws {
        let abc = Array("abc".utf8)
        var stream = Sha256()
        try stream.update(abc, offset: 0, length: 2)
        let before = stream.digest()
        for (offset, length) in [(-1, 2), (0, -1), (1, Int.max), (abc.count + 1, 0)] {
            XCTAssertThrowsError(try stream.update(abc, offset: offset, length: length)) {
                XCTAssertEqual($0 as? Sha256.InputError, Sha256.InputError.invalidRange)
            }
            XCTAssertEqual(stream.digest(), before)
        }

        var copy = stream
        try copy.update(abc, offset: 2, length: 1)
        XCTAssertEqual(copy.digest(), reference(abc))
        XCTAssertEqual(stream.digest(), before)

        var mutableInput = abc
        var owned = Sha256()
        try owned.update(mutableInput)
        mutableInput[0] = 0
        var returned = owned.digest()
        returned[0] = 0
        XCTAssertEqual(owned.digest(), reference(abc))

        let maximum = Sha256.maxMessageBytes
        XCTAssertEqual(try Sha256.checkedLength(maximum, 0), maximum)
        XCTAssertEqual(try Sha256.checkedLength(maximum - 1, 1), maximum)
        XCTAssertThrowsError(try Sha256.checkedLength(maximum, 1)) {
            XCTAssertEqual($0 as? Sha256.InputError, Sha256.InputError.messageTooLong)
        }
        XCTAssertThrowsError(try Sha256.checkedLength(maximum - 1, 2)) {
            XCTAssertEqual($0 as? Sha256.InputError, Sha256.InputError.messageTooLong)
        }
    }
}

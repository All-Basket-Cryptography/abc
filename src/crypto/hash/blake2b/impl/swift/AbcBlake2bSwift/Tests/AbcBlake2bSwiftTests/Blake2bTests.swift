import Foundation
import XCTest
@testable import AbcBlake2bSwift

final class Blake2bTests: XCTestCase {
    func testKnownAnswersAndStreaming() throws {
        let abc = Array("abc".utf8)
        let expected = try decode("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d"
            + "87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
        XCTAssertEqual(try Blake2b.hash(abc), expected)
        XCTAssertThrowsError(try Blake2b(digestSize: 0)) { error in
            XCTAssertEqual(error as? Blake2bError, .invalidDigestSize)
        }
        XCTAssertThrowsError(try Blake2b.hash(abc, digestSize: 65))

        let nearCarry = ByteCounter(low: .max - 127, high: .max - 1)
        XCTAssertEqual(nearCarry.adding(128), ByteCounter(low: 0, high: .max))
        let limit = ByteCounter(low: .max, high: .max)
        XCTAssertEqual(limit.adding(0), limit)
        XCTAssertNil(limit.adding(1))

        var initial = try Blake2b()
        try initial.update(Array("a".utf8))
        var copy = initial
        try copy.update(Array("bc".utf8))
        XCTAssertEqual(copy.digest(), expected)
        XCTAssertEqual(initial.digest(), try Blake2b.hash(Array("a".utf8)))

        if let path = ProcessInfo.processInfo.environment["ABC_BLAKE2B_FIXTURES"] {
            try verifyFixtures(try String(contentsOfFile: path, encoding: .utf8))
        }
    }

    private func verifyFixtures(_ fixtures: String) throws {
        var lines = fixtures.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertEqual(lines.popLast(), "")
        XCTAssertEqual(lines.count % 4, 0)
        guard lines.count % 4 == 0 else { return }
        var known = 0, openssl = 0, variable = 0, snapshots = 0, splits = 0
        for offset in stride(from: 0, to: lines.count, by: 4) {
            switch lines[offset] {
            case "known": known += 1
            case "openssl": openssl += 1
            case "variable": variable += 1
            default:
                XCTFail("Unknown fixture role")
                continue
            }
            let input = try decode(String(lines[offset + 1]))
            let expected = try decode(String(lines[offset + 2]))
            let prefix = try decode(String(lines[offset + 3]))
            let size = expected.count
            XCTAssertEqual(try Blake2b.hash(input, digestSize: size), expected)
            var stream = try Blake2b(digestSize: size)
            let middle = input.count / 2
            try stream.update(input.prefix(middle))
            XCTAssertEqual(stream.digest(), prefix)
            try stream.update(input.dropFirst(middle))
            XCTAssertEqual(stream.digest(), expected)
            snapshots += 1
            if input.count <= 257 && [1, 31, 64].contains(size) {
                for split in 0...input.count {
                    stream.reset()
                    try stream.update(input.prefix(split))
                    try stream.update([UInt8]())
                    try stream.update(input.dropFirst(split))
                    XCTAssertEqual(stream.digest(), expected)
                    splits += 1
                }
            }
        }
        XCTAssertEqual(known, 5)
        XCTAssertEqual(openssl, 139)
        XCTAssertEqual(variable, 697)
        XCTAssertEqual(snapshots, 841)
        XCTAssertEqual(splits, 4926)
        print("known_answers=\(known)")
        print("openssl_comparisons=\(openssl)")
        print("hashlib_comparisons=\(variable)")
        print("snapshots=\(snapshots)")
        print("streaming_splits=\(splits)")
    }

    private func decode(_ hex: String) throws -> [UInt8] {
        let bytes = Array(hex.utf8)
        guard bytes.count % 2 == 0 else { throw FixtureError.invalidHex }
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count / 2)
        for i in stride(from: 0, to: bytes.count, by: 2) {
            result.append(try digit(bytes[i]) << 4 | digit(bytes[i + 1]))
        }
        return result
    }

    private func digit(_ character: UInt8) throws -> UInt8 {
        switch character {
        case 48...57: return character - 48
        case 97...102: return character - 87
        default: throw FixtureError.invalidHex
        }
    }

    private enum FixtureError: Error { case invalidHex }
}

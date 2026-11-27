import AbcShake256Swift
import Foundation
import XCTest

final class Shake256Tests: XCTestCase {
    private struct Fixture: Decodable {
        let known: Bool
        let input: Data
        let expected: Data
        let prefix: Data
    }

    func testKnownAnswersAndOpenSSL() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "oracle", withExtension: "json"))
        let fixtures = try JSONDecoder().decode([Fixture].self, from: Data(contentsOf: url))
        XCTAssertEqual(fixtures.count, 62)
        XCTAssertEqual(fixtures.filter(\.known).count, 3)
        var splits = 0
        for fixture in fixtures {
            let input = Array(fixture.input)
            let expected = Array(fixture.expected)
            XCTAssertEqual(try Shake256.xof(input, count: expected.count), expected)
            let midpoint = input.count / 2
            var stream = Shake256()
            var caller = Array(input.prefix(midpoint))
            stream.update(caller)
            for i in caller.indices { caller[i] = 0 }
            var prefix = stream.finalize()
            stream.update(Array(input.dropFirst(midpoint)))
            XCTAssertEqual(try prefix.read(fixture.prefix.count), Array(fixture.prefix))
            var result = stream.finalize()
            XCTAssertEqual(try result.read(expected.count), expected)
            if input.count <= 273 && expected.count <= 512 {
                for split in 0...input.count {
                    stream.reset()
                    stream.update(Array(input.prefix(split)))
                    stream.update([])
                    stream.update(Array(input.dropFirst(split)))
                    var reader = stream.finalize()
                    var next: [UInt8] = []
                    for count in [0, 1, 7, 127, 1, 136, 137, 512] {
                        let amount = min(count, expected.count - next.count)
                        var part = [UInt8](repeating: 0xa5, count: amount)
                        reader.read(into: &part)
                        next.append(contentsOf: part)
                    }
                    XCTAssertEqual(next, expected)
                    splits += 1
                }
            }
        }
        let shrink = Shake256()
        var rejected = shrink.finalize()
        XCTAssertThrowsError(try rejected.read(-1))
        XCTAssertThrowsError(try Shake256.xof([], count: -1))
        XCTAssertEqual(try rejected.read(256), try Shake256.xof([], count: 256))
        print("known_answers=\(fixtures.filter(\.known).count)")
        print("oracle_comparisons=\(fixtures.filter { !$0.known }.count)")
        print("streaming_splits=\(splits)")
    }
}

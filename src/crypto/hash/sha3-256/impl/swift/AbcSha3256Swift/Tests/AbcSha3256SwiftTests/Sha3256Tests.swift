import AbcSha3256Swift
import Foundation
import XCTest

final class Sha3256Tests: XCTestCase {
    private struct Fixture: Decodable {
        let known: Bool
        let input: Data
        let expected: Data
        let prefix: Data
    }

    func testKnownAnswersAndOpenSSL() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "oracle", withExtension: "json"))
        let fixtures = try JSONDecoder().decode([Fixture].self, from: Data(contentsOf: url))
        XCTAssertEqual(fixtures.count, 44)
        XCTAssertEqual(fixtures.filter(\.known).count, 3)
        var splits = 0
        for fixture in fixtures {
            let input = Array(fixture.input)
            let expected = Array(fixture.expected)
            XCTAssertEqual(Sha3256.hash(input), expected)
            let midpoint = input.count / 2
            var stream = Sha3256()
            var caller = Array(input.prefix(midpoint))
            stream.update(caller)
            for i in caller.indices { caller[i] = 0 }
            XCTAssertEqual(stream.digest(), Array(fixture.prefix))
            let snapshot = stream
            stream.update(Array(input.dropFirst(midpoint)))
            XCTAssertEqual(stream.digest(), expected)
            XCTAssertEqual(snapshot.digest(), Array(fixture.prefix))
            if input.count <= 273 {
                for split in 0...input.count {
                    stream.reset()
                    stream.update(Array(input.prefix(split)))
                    stream.update([])
                    stream.update(Array(input.dropFirst(split)))
                    XCTAssertEqual(stream.digest(), expected)
                    XCTAssertEqual(stream.digest(), expected)
                    splits += 1
                }
            }
        }
        print("known_answers=\(fixtures.filter(\.known).count)")
        print("oracle_comparisons=\(fixtures.filter { !$0.known }.count)")
        print("streaming_splits=\(splits)")
    }
}

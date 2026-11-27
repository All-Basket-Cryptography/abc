import AbcKeccakP1600Swift
import Foundation
import XCTest

final class KeccakP1600Tests: XCTestCase {
    private struct Fixture: Decodable {
        let known: Bool
        let input: Data
        let expected: Data
    }

    private func lanes(_ data: Data) throws -> [UInt64] {
        let bytes = Array(data)
        _ = try XCTUnwrap(bytes.count == 200 ? bytes.count : nil)
        return (0..<25).map { lane in
            var word: UInt64 = 0
            for i in 0..<8 {
                word |= UInt64(bytes[lane * 8 + i]) << (8 * i)
            }
            return word
        }
    }

    func testPublishedStateAndIndependentOracle() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "oracle", withExtension: "json"))
        let fixtures = try JSONDecoder().decode([Fixture].self, from: Data(contentsOf: url))
        XCTAssertEqual(fixtures.count, 17)
        XCTAssertEqual(fixtures.filter(\.known).count, 1)
        for fixture in fixtures {
            var state = try lanes(fixture.input)
            try KeccakP1600.permute(&state)
            XCTAssertEqual(state, try lanes(fixture.expected))
        }
        var invalid = [UInt64](repeating: 13, count: 24)
        let original = invalid
        XCTAssertThrowsError(try KeccakP1600.permute(&invalid))
        XCTAssertEqual(invalid, original)
        print("known_answers=\(fixtures.filter(\.known).count)")
        print("oracle_comparisons=\(fixtures.filter { !$0.known }.count)")
        print("streaming_splits=0")
    }
}

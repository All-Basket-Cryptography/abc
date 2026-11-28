import AbcScryptSwift
import Foundation
import XCTest

final class ScryptTests: XCTestCase {
    private struct Row: Decodable {
        let password: String
        let salt: String
        let cost: Int
        let blockSize: Int
        let parallel: Int
        let output: String
    }

    private func hex(_ value: String) throws -> [UInt8] {
        let units = Array(value.utf8)
        return try stride(from: 0, to: units.count, by: 2).map { index in
            try XCTUnwrap(UInt8(String(decoding: units[index..<(index + 2)], as: UTF8.self), radix: 16))
        }
    }

    func testPublishedAndIndependentCases() throws {
        let examples: [(password: [UInt8], salt: [UInt8], cost: Int, block: Int, parallel: Int, answer: String)] = [
            ([], [], 16, 1, 1,
             "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fc" +
             "d0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
            (Array("password".utf8), Array("NaCl".utf8), 1024, 8, 16,
             "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622" +
             "eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
        ]
        for example in examples {
            let work = try Scrypt.workspaceSize(cost: example.cost, blockSize: example.block,
                                                parallel: example.parallel)
            let actual = try Scrypt.derive(password: example.password, salt: example.salt, cost: example.cost,
                                            blockSize: example.block, parallel: example.parallel,
                                            length: 64, memoryLimit: work + 64)
            XCTAssertEqual(actual, try hex(example.answer))
        }
        let path = try XCTUnwrap(ProcessInfo.processInfo.environment["ABC_SCRYPT_FIXTURES"])
        let rows = try JSONDecoder().decode([Row].self, from: Data(contentsOf: URL(fileURLWithPath: path)))
        XCTAssertEqual(rows.count, 144)
        for row in rows {
            let expected = try hex(row.output)
            let password = try hex(row.password)
            let salt = try hex(row.salt)
            let work = try Scrypt.workspaceSize(cost: row.cost, blockSize: row.blockSize, parallel: row.parallel)
            XCTAssertEqual(try Scrypt.derive(password: password, salt: salt, cost: row.cost,
                                            blockSize: row.blockSize, parallel: row.parallel, length: expected.count,
                                            memoryLimit: work + expected.count), expected)
            XCTAssertThrowsError(try Scrypt.derive(password: password, salt: salt, cost: row.cost,
                                                  blockSize: row.blockSize, parallel: row.parallel, length: expected.count,
                                                  memoryLimit: work + expected.count - 1)) { error in
                XCTAssertEqual(error as? Scrypt.InputError, .memoryLimit)
            }
        }
        XCTAssertThrowsError(try Scrypt.workspaceSize(cost: 65_536, blockSize: 1, parallel: 1))
        XCTAssertThrowsError(try Scrypt.workspaceSize(cost: 3, blockSize: 1, parallel: 1))
        XCTAssertThrowsError(try Scrypt.workspaceSize(cost: 2, blockSize: Int.max, parallel: 1))
        print("known_answers=2")
        print("openssl_comparisons=144")
        print("budget_rejections=144")
    }
}

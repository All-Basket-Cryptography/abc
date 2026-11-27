import AbcPbkdf2Sha256Swift
import CryptoKit
import Foundation
import XCTest

final class Pbkdf2Sha256Tests: XCTestCase {
    private func reference(_ password: [UInt8], _ salt: [UInt8], _ rounds: UInt32, _ length: Int) -> [UInt8] {
        let key = SymmetricKey(data: Data(password.isEmpty ? [UInt8](repeating: 0, count: 64) : password))
        func authenticate(_ message: [UInt8]) -> [UInt8] {
            Array(HMAC<CryptoKit.SHA256>.authenticationCode(for: Data(message), using: key))
        }
        let blocks = (length + 31) / 32
        let result = (1...blocks).flatMap { index in
            let counter = withUnsafeBytes(of: UInt32(index).bigEndian) { Array($0) }
            var terms = [authenticate(salt + counter)]
            for _ in 1..<rounds {
                terms.append(authenticate(terms[terms.count - 1]))
            }
            return terms.dropFirst().reduce(terms[0]) { partial, term in
                zip(partial, term).map { $0.0 ^ $0.1 }
            }
        }
        return Array(result.prefix(length))
    }

    func testRfc7914() throws {
        let cases: [(String, String, UInt32, String)] = [
            ("passwd", "salt", 1,
             "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
            ("Password", "NaCl", 80_000,
             "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
        ]
        for (password, salt, rounds, expected) in cases {
            let value = try Pbkdf2Sha256.derive(password: Array(password.utf8), salt: Array(salt.utf8),
                                               iterations: rounds, length: 64)
            XCTAssertEqual(value.map { String(format: "%02x", $0) }.joined(), expected)
        }
        print("known_answers=2")
    }

    func testProviderAndBounds() throws {
        var comparisons = 0
        for passwordLength in [0, 1, 32, 63, 64, 65, 1024] {
            let password = (0..<passwordLength).map { UInt8(truncatingIfNeeded: $0 * 13 + 1) }
            for length in [1, 31, 32, 33, 63, 64, 65, 95] {
                let salt = (0..<(length % 67)).map { UInt8(truncatingIfNeeded: $0 * 19 + 5) }
                let rounds = UInt32(length % 5 + 1)
                let value = try Pbkdf2Sha256.derive(password: password, salt: salt, iterations: rounds, length: length)
                XCTAssertEqual(value, reference(password, salt, rounds, length))
                comparisons += 1
            }
        }
        XCTAssertThrowsError(try Pbkdf2Sha256.derive(password: [], salt: [], iterations: 0, length: 1)) {
            XCTAssertEqual($0 as? Pbkdf2Sha256.InputError, Pbkdf2Sha256.InputError.iterations)
        }
        for length in [Int.min, 0, Int(Pbkdf2Sha256.maxOutputBytes + 1)] {
            XCTAssertThrowsError(try Pbkdf2Sha256.derive(password: [], salt: [], iterations: 1, length: length)) {
                XCTAssertEqual($0 as? Pbkdf2Sha256.InputError, Pbkdf2Sha256.InputError.outputLength)
            }
        }
        print("provider_comparisons=\(comparisons)")
    }
}

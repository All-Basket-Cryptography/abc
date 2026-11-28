import AbcHkdfSha256Swift
import CryptoKit
import Foundation
import XCTest

final class HkdfSha256Tests: XCTestCase {
    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    func testRfc5869() throws {
        let ikm = [UInt8](repeating: 0x0b, count: 22)
        let salt = (0..<13).map { UInt8($0) }
        let info = (0xf0..<0xfa).map { UInt8($0) }
        let prk = try HkdfSha256.extract(salt: salt, inputKeyMaterial: ikm)
        XCTAssertEqual(hex(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        XCTAssertEqual(hex(try HkdfSha256.expand(prk: prk, info: info, length: 42)), expected)
        XCTAssertEqual(hex(try HkdfSha256.derive(salt: salt, inputKeyMaterial: ikm, info: info, length: 42)), expected)

        let defaultPrk = try HkdfSha256.extract(inputKeyMaterial: ikm)
        XCTAssertEqual(hex(defaultPrk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        let defaultOkm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        XCTAssertEqual(hex(try HkdfSha256.derive(inputKeyMaterial: ikm, info: [], length: 42)), defaultOkm)
        print("known_answers=2")
    }

    func testProviderAndLimits() throws {
        var comparisons = 0
        let ikm = (0..<139).map { UInt8(truncatingIfNeeded: $0 * 31 + 9) }
        for saltLength in [0, 1, 32, 64, 65, 131] {
            let salt = (0..<saltLength).map { UInt8(truncatingIfNeeded: $0 * 13 + 1) }
            for length in [1, 31, 32, 33, 63, 64, 65, 255, 8159, 8160] {
                let info = (0..<(length % 67)).map { UInt8(truncatingIfNeeded: $0 * 19 + 5) }
                let oracle = HKDF<CryptoKit.SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data(ikm)),
                                                            salt: Data(salt), info: Data(info), outputByteCount: length)
                let material = oracle.withUnsafeBytes { Array($0) }
                XCTAssertEqual(try HkdfSha256.derive(salt: salt, inputKeyMaterial: ikm, info: info, length: length), material)
                comparisons += 1
            }
        }
        let prk = try HkdfSha256.extract(inputKeyMaterial: ikm)
        XCTAssertEqual(try HkdfSha256.expand(prk: prk, info: [], length: 0), [])
        XCTAssertThrowsError(try HkdfSha256.expand(prk: Array(prk.dropLast()), info: [], length: 0)) {
            XCTAssertEqual($0 as? HkdfSha256.InputError, HkdfSha256.InputError.shortPrk)
        }
        for length in [-1, 8161, Int.max] {
            XCTAssertThrowsError(try HkdfSha256.expand(prk: prk, info: [], length: length)) {
                XCTAssertEqual($0 as? HkdfSha256.InputError, HkdfSha256.InputError.outputLength)
            }
        }
        print("provider_comparisons=\(comparisons)")
    }
}

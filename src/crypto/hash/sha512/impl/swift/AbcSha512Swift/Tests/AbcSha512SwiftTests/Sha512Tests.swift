import CryptoKit
import Foundation
import XCTest
import AbcSha512Swift

final class Sha512Tests: XCTestCase {
    func testKnownAnswers() throws {
        let vectors: [([UInt8], String)] = [
            ([], "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (Array("abc".utf8), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            ([UInt8](repeating: 97, count: 1_000_000), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                + "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"),
        ]
        for (message, expected) in vectors {
            let output = try Sha512.hash(message)
            XCTAssertEqual(output.map { String(format: "%02x", $0) }.joined(), expected)
        }
        print("known_answers=3")
    }

    func testProviderAndBoundarySplits() throws {
        var comparisons = 0
        var snapshots = 0
        for size in [0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257, 1025] {
            let bytes = (0..<size).map { index in UInt8(truncatingIfNeeded: index * index + 31 * index + 7) }
            let expected = Array(CryptoKit.SHA512.hash(data: Data(bytes)))
            XCTAssertEqual(try Sha512.hash(bytes), expected)
            comparisons += 1
            for split in 0...size {
                var stream = Sha512()
                var prefix = Array(bytes.prefix(split))
                try stream.update(prefix)
                for i in prefix.indices { prefix[i] = 0 }
                let interim = Array(CryptoKit.SHA512.hash(data: Data(bytes.prefix(split))))
                XCTAssertEqual(stream.digest(), interim)
                let checkpoint = stream
                try stream.update(Array(bytes.dropFirst(split)))
                XCTAssertEqual(stream.digest(), expected)
                XCTAssertEqual(checkpoint.digest(), interim)
                stream.reset()
                XCTAssertEqual(stream.digest(), Array(CryptoKit.SHA512.hash(data: Data())))
                snapshots += 3
            }
        }
        print("provider_comparisons=\(comparisons)")
        print("streaming_snapshots=\(snapshots)")
    }
}

import AbcAes256Swift
import CommonCrypto
import Dispatch
import Foundation

func check() throws {
    let rows = try fixtures()
    for row in rows {
        let cipher = try Aes256(key: row[0])
        ensure(try cipher.encryptBlock(row[1]) == row[3], "AES-256 block encryption")
        ensure(try cipher.decryptBlock(row[2]) == row[4], "AES-256 block decryption")
    }
    for length in [0, 16, 24, 31, 33] {
        rejects(Aes256Error.invalidKeySize) { _ = try Aes256(key: Data(repeating: 0, count: length)) }
    }
    let valid = try Aes256(key: Data(repeating: 0, count: 32))
    for length in [0, 1, 15, 17, 32] {
        let block = Data(repeating: 0, count: length)
        rejects(Aes256Error.invalidBlockSize) { _ = try valid.encryptBlock(block) }
        rejects(Aes256Error.invalidBlockSize) { _ = try valid.decryptBlock(block) }
    }
    print("cases=\(rows.count)")
    print("bounds=passed")
}

func benchmark() throws {
    let iterations = 20_000
    let trials = 7
    let key = Data(repeating: 0, count: 32)
    let plaintext = Data(repeating: 0, count: 16)
    let cipher = try Aes256(key: key)
    let expected = try cipher.encryptBlock(plaintext)
    let rawKey = Array(key)
    let rawInput = Array(plaintext)
    var rawOutput = [UInt8](repeating: 0, count: 16)
    func provider() {
        var written = 0
        let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                             rawKey, rawKey.count, nil, rawInput, rawInput.count, &rawOutput, 16, &written)
        ensure(status == kCCSuccess && written == 16, "Benchmark direct CommonCrypto block")
    }
    func measure(_ work: () throws -> Void) rethrows -> Double {
        for _ in 0..<iterations { try work() }
        var samples: [Double] = []
        for _ in 0..<trials {
            let start = DispatchTime.now().uptimeNanoseconds
            for _ in 0..<iterations { try work() }
            samples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / Double(iterations))
        }
        return samples.sorted()[trials / 2]
    }
    var observed = Data()
    let wrapper = try measure { observed = try cipher.encryptBlock(plaintext) }
    let direct = measure { provider() }
    ensure(observed == expected && Data(rawOutput) == expected, "Benchmark AES ciphertext")
    print("wrapper_ns=\(wrapper)")
    print("provider_ns=\(direct)")
    print("iterations=\(iterations)")
    print("trials=\(trials)")
}

if CommandLine.arguments[1] == "--benchmark" {
    try benchmark()
} else {
    try check()
}

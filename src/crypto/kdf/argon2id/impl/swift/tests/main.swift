import AbcArgon2idSwift
import Foundation

func check() throws {
    let input = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
    let lines = input.split(separator: "\n")
    for line in lines {
        let row = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        let tag = try Argon2id.derive(password: decode(row[4]), salt: decode(row[5]), secret: decode(row[6]),
            associatedData: decode(row[7]), memoryKiB: UInt32(row[0])!, passes: UInt32(row[1])!,
            lanes: UInt32(row[2])!, tagBytes: UInt32(row[3])!, memoryLimit: 4_500_000)
        ensure(tag == decode(row[8]), "Argon2id Go or RFC comparison")
    }
    let salt = Data(repeating: 2, count: 8)
    rejects(Argon2idError.memoryBudgetExceeded) {
        _ = try Argon2id.derive(password: Data(), salt: salt, memoryKiB: 8, passes: 1, lanes: 1,
                               tagBytes: 4, memoryLimit: 8195)
    }
    for (memory, passes, lanes, tag) in [(7, 1, 1, 4), (8, 0, 1, 4), (8, 1, 0, 4), (8, 1, 1, 3)] {
        rejects(Argon2idError.invalidParameters) {
            _ = try Argon2id.derive(password: Data(), salt: salt, memoryKiB: UInt32(memory), passes: UInt32(passes),
                                   lanes: UInt32(lanes), tagBytes: UInt32(tag), memoryLimit: UInt64.max)
        }
    }
    rejects(Argon2idError.invalidParameters) {
        _ = try Argon2id.derive(password: Data(), salt: salt.dropLast(), memoryKiB: 8, passes: 1, lanes: 1,
                               tagBytes: 4, memoryLimit: UInt64.max)
    }
    print("cases=\(lines.count)")
    print("bounds=passed")
}

try check()

import Foundation

func decode(_ text: Substring) -> Data {
    let bytes = Array(text.utf8)
    precondition(bytes.count.isMultiple(of: 2))
    return Data(stride(from: 0, to: bytes.count, by: 2).map { i in
        UInt8(String(decoding: bytes[i..<(i + 2)], as: UTF8.self), radix: 16)!
    })
}

func fixtures() throws -> [[Data]] {
    let content = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
    return content.split(separator: "\n").map { line in
        line.split(separator: ":", omittingEmptySubsequences: false).map(decode)
    }
}

func ensure(_ condition: Bool, _ reason: String) {
    precondition(condition, reason)
}

func rejects<T: Error & Equatable>(_ expected: T, _ body: () throws -> Void) {
    do {
        try body()
    } catch {
        ensure((error as? T) == expected, "Unexpected API error: \(error)")
        return
    }
    preconditionFailure("Expected API error: \(expected)")
}

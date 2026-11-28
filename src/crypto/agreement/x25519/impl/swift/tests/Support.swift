import Foundation

func decode(_ text: String) -> Data {
    let bytes = Array(text.utf8)
    precondition(bytes.count.isMultiple(of: 2))
    return Data(stride(from: 0, to: bytes.count, by: 2).map { i in
        UInt8(String(decoding: bytes[i..<(i + 2)], as: UTF8.self), radix: 16)!
    })
}

func rows() throws -> [[Data]] {
    let fixture = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
    return fixture.split(separator: "\n").map { line in
        line.split(separator: ":", omittingEmptySubsequences: false).map { decode(String($0)) }
    }
}

func ensure(_ condition: Bool, _ description: String) {
    precondition(condition, description)
}

func rejects<T: Error & Equatable>(_ expected: T, _ body: () throws -> Void) {
    do {
        try body()
    } catch {
        ensure((error as? T) == expected, "Unexpected error: \(error)")
        return
    }
    preconditionFailure("Expected error: \(expected)")
}

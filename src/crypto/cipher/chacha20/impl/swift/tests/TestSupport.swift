import Foundation

let rfcMessage = decode(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a" +
    "204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f72207468" +
    "65206675747572652c2073756e73637265656e20776f756c642062652069742e"
)

func decode(_ text: String) -> [UInt8] {
    let bytes = Array(text.utf8)
    precondition(bytes.count.isMultiple(of: 2))
    return stride(from: 0, to: bytes.count, by: 2).map { i in
        UInt8(String(decoding: bytes[i..<(i + 2)], as: UTF8.self), radix: 16)!
    }
}

func wire(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func fixtures() throws -> [[String]] {
    let path = CommandLine.arguments[1]
    let content = try String(contentsOfFile: path, encoding: .utf8)
    return content.split(separator: "\n").map { line in
        line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
    }
}

func ensure(_ condition: Bool, _ reason: String) {
    precondition(condition, reason)
}

func rejects(_ reason: String, _ body: () throws -> Void) {
    do {
        try body()
    } catch {
        return
    }
    preconditionFailure(reason)
}

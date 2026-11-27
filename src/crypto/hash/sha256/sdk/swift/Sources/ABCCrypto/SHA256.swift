import CABCCrypto
import Foundation

public enum ABCError: Error, Equatable {
    case incompatibleABI(UInt32)
    case nativeStatus(Int32)
    case missingProvider
}

private func checkABI() throws {
    let abi = abc_abi_version()
    guard abi == 0x0001_0000 else {
        throw ABCError.incompatibleABI(abi)
    }
}

private func check(_ status: Int32) throws {
    guard status == 0 else { throw ABCError.nativeStatus(status) }
}

public enum SHA256 {
    public static func implementation() throws -> String {
        try checkABI()
        guard let identifier = abc_sha256_implementation() else {
            throw ABCError.missingProvider
        }
        return String(cString: identifier)
    }

    public static func digest(_ bytes: [UInt8]) throws -> [UInt8] {
        try checkABI()
        var result = [UInt8](repeating: 0, count: 32)
        let status = bytes.withUnsafeBufferPointer { input in
            result.withUnsafeMutableBufferPointer { output in
                abc_sha256_digest(input.baseAddress, input.count, output.baseAddress, output.count)
            }
        }
        try check(status)
        return result
    }
}

public final class SHA256Stream {
    private var handle: OpaquePointer?
    private let lock = NSLock()

    public init() throws {
        try checkABI()
        var context: OpaquePointer? = nil
        try check(abc_sha256_new(&context))
        guard let context else { throw ABCError.nativeStatus(Int32(ABC_ERROR_STATE)) }
        handle = context
    }

    deinit { abc_sha256_free(handle) }

    private func withContext<Result>(_ operation: (OpaquePointer) throws -> Result) throws -> Result {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw ABCError.nativeStatus(Int32(ABC_ERROR_STATE)) }
        return try operation(handle)
    }

    public func update(_ bytes: [UInt8]) throws {
        try withContext { context in
            let status = bytes.withUnsafeBufferPointer { input in
                abc_sha256_update(context, input.baseAddress, input.count)
            }
            try check(status)
        }
    }

    public func finish() throws -> [UInt8] {
        try withContext { context in
            var result = [UInt8](repeating: 0, count: 32)
            let status = result.withUnsafeMutableBufferPointer { output in
                abc_sha256_finalize(context, output.baseAddress, output.count)
            }
            try check(status)
            return result
        }
    }

    public func reset() throws {
        try withContext { try check(abc_sha256_reset($0)) }
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        abc_sha256_free(handle)
        handle = nil
    }
}

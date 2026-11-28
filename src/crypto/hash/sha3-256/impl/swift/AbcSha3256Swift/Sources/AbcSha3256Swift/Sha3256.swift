import AbcKeccakP1600Swift

public struct Sha3256: Sendable {
    public static let digestSize = 32
    private var sponge = Sponge136()

    public init() {}

    public mutating func update(_ bytes: [UInt8]) { sponge.absorb(bytes) }

    public func digest() -> [UInt8] {
        var reader = sponge.finish(.sha3)
        var output = [UInt8](repeating: 0, count: Self.digestSize)
        reader.read(into: &output)
        return output
    }

    public mutating func reset() { sponge.reset() }

    public static func hash(_ bytes: [UInt8]) -> [UInt8] {
        var stream = Self()
        stream.update(bytes)
        return stream.digest()
    }
}

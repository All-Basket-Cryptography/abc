import AbcKeccakP1600Swift

public struct Shake256: Sendable {
    private var sponge = Sponge136()

    public init() {}

    public mutating func update(_ bytes: [UInt8]) { sponge.absorb(bytes) }

    public func finalize() -> SpongeReader { sponge.finish(.shake) }

    public mutating func reset() { sponge.reset() }

    public static func xof(_ bytes: [UInt8], count: Int) throws -> [UInt8] {
        guard count >= 0 else { throw KeccakError.invalidOutputLength }
        var stream = Self()
        stream.update(bytes)
        var reader = stream.finalize()
        return try reader.read(count)
    }
}

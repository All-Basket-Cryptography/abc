import CryptoKit
import Foundation

public enum Ed25519Error: Error, Equatable {
    case invalidSeedSize
}

public enum Ed25519 {
    public static let seedBytes = 32
    public static let publicKeyBytes = 32
    public static let signatureBytes = 64

    public static func publicKey(seed: Data) throws -> Data {
        try decodeSeed(seed).publicKey.rawRepresentation
    }

    public static func sign(seed: Data, message: Data) throws -> Data {
        try decodeSeed(seed).signature(for: message)
    }

    public static func verifyStrict(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard publicKey.count == publicKeyBytes, signature.count == signatureBytes else { return false }
        let encodedSignature = Array(signature)
        guard smallerThan(encodedSignature.suffix(32), order),
              validPoint(Array(publicKey)),
              validPoint(Array(encodedSignature.prefix(32))),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return key.isValidSignature(signature, for: message)
    }

    private static let order: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]
    private static let prime = [UInt8(0xed)] + [UInt8](repeating: 0xff, count: 30) + [0x7f]
    private static let torsionY = [
        [UInt8](repeating: 0, count: 32),
        [UInt8(1)] + [UInt8](repeating: 0, count: 31),
        [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
         0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
        [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
         0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
        [UInt8(0xec)] + [UInt8](repeating: 0xff, count: 30) + [0x7f],
    ]

    private static func decodeSeed(_ seed: Data) throws -> Curve25519.Signing.PrivateKey {
        guard seed.count == seedBytes else { throw Ed25519Error.invalidSeedSize }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    private static func smallerThan(_ left: ArraySlice<UInt8>, _ right: [UInt8]) -> Bool {
        left.reversed().lexicographicallyPrecedes(right.reversed())
    }

    private static func validPoint(_ encoded: [UInt8]) -> Bool {
        var y = encoded
        y[31] &= 0x7f
        // The complete torsion list also removes the x=0 encodings with a set sign bit.
        guard smallerThan(y[...], prime), !torsionY.contains(y) else { return false }
        return PublicField.onCurve(y)
    }
}

// Public-input arithmetic only. CryptoKit handles the secret-key operations.
private struct PublicField: Equatable {
    private static let width = 51
    private static let mask = (UInt64(1) << width) - 1
    private static let prime: [UInt64] = [mask - 18, mask, mask, mask, mask]
    private static let one = PublicField([1, 0, 0, 0, 0])
    private static let d = PublicField([
        929955233495203, 466365720129213, 1662059464998953, 2033849074728123, 1442794654840575,
    ])
    private let digits: [UInt64]

    private init(_ digits: [UInt64]) {
        self.digits = digits
    }

    static func onCurve(_ y: [UInt8]) -> Bool {
        let y2 = PublicField(yBytes: y).squared()
        let numerator = y2.subtracting(one)
        let denominator = d.multiplied(by: y2).adding(one)
        // A nonzero a/b is a square exactly when a*b is a square.
        // The caller has already rejected the y=±1 encodings with zero numerator.
        return numerator.multiplied(by: denominator).quadraticCharacter() == one
    }

    private init(yBytes: [UInt8]) {
        var digits = [UInt64](repeating: 0, count: 5)
        for index in yBytes.indices {
            let bit = 8 * index
            let limb = bit / Self.width
            let shift = bit % Self.width
            let byte = UInt64(yBytes[index])
            digits[limb] |= (byte << shift) & Self.mask
            if shift > Self.width - 8 && limb < 4 {
                digits[limb + 1] |= byte >> (Self.width - shift)
            }
        }
        self.init(digits)
    }

    private func adding(_ rhs: Self) -> Self {
        Self.reduce((0..<5).map { UInt128(digits[$0]) + UInt128(rhs.digits[$0]) })
    }

    private func subtracting(_ rhs: Self) -> Self {
        Self.reduce((0..<5).map { UInt128(digits[$0] + 2 * Self.prime[$0] - rhs.digits[$0]) })
    }

    private func multiplied(by rhs: Self) -> Self {
        var product = [UInt128](repeating: 0, count: 5)
        for i in 0..<5 {
            for j in 0..<5 {
                let term = UInt128(digits[i]) * UInt128(rhs.digits[j])
                let index = i + j
                if index < 5 { product[index] += term }
                else { product[index - 5] += 19 * term }
            }
        }
        return Self.reduce(product)
    }

    private func squared(_ times: Int = 1) -> Self {
        var state = self
        for _ in 0..<times { state = state.multiplied(by: state) }
        return state
    }

    private func quadraticCharacter() -> Self {
        // a^(2^254 - 10) gives the quadratic character modulo 2^255 - 19.
        let a2 = squared()
        let a9 = a2.squared(2).multiplied(by: self)
        let a11 = a9.multiplied(by: a2)
        let a31 = a11.squared().multiplied(by: a9)
        let a10 = a31.squared(5).multiplied(by: a31)
        let a20 = a10.squared(10).multiplied(by: a10)
        let a40 = a20.squared(20).multiplied(by: a20)
        let a50 = a40.squared(10).multiplied(by: a10)
        let a100 = a50.squared(50).multiplied(by: a50)
        let a200 = a100.squared(100).multiplied(by: a100)
        let a250 = a200.squared(50).multiplied(by: a50)
        let a6 = a2.squared().multiplied(by: a2)
        return a250.squared(4).multiplied(by: a6)
    }

    private static func reduce(_ raw: [UInt128]) -> Self {
        var limbs = raw
        for _ in 0..<3 {
            for index in 0..<4 {
                limbs[index + 1] += limbs[index] >> width
                limbs[index] &= UInt128(mask)
            }
            limbs[0] += 19 * (limbs[4] >> width)
            limbs[4] &= UInt128(mask)
        }
        let result = limbs.map { UInt64($0) }
        if result[0] >= prime[0] && result[1...].allSatisfy({ $0 == mask }) {
            return Self([result[0] - prime[0], 0, 0, 0, 0])
        }
        return Self(result)
    }
}

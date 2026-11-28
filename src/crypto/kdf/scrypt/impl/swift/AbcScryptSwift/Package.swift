// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AbcScryptSwift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcScryptSwift", targets: ["AbcScryptSwift"])],
    dependencies: [
        .package(path: "../../../../pbkdf2-hmac-sha256/impl/swift/AbcPbkdf2Sha256Swift"),
    ],
    targets: [
        .target(name: "AbcScryptSwift", dependencies: [
            .product(name: "AbcPbkdf2Sha256Swift", package: "abcpbkdf2sha256swift"),
        ]),
        .testTarget(name: "AbcScryptSwiftTests", dependencies: ["AbcScryptSwift"]),
    ],
)

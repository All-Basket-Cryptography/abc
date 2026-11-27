// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcPbkdf2Sha256Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcPbkdf2Sha256Swift", targets: ["AbcPbkdf2Sha256Swift"])],
    dependencies: [.package(path: "../../../../../mac/hmac-sha256/impl/swift/AbcHmacSha256Swift")],
    targets: [
        .target(name: "AbcPbkdf2Sha256Swift", dependencies: [
            .product(name: "AbcHmacSha256Swift", package: "abchmacsha256swift"),
        ]),
        .testTarget(name: "AbcPbkdf2Sha256SwiftTests", dependencies: ["AbcPbkdf2Sha256Swift"]),
    ]
)

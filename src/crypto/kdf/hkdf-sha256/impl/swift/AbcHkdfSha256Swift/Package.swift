// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcHkdfSha256Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcHkdfSha256Swift", targets: ["AbcHkdfSha256Swift"])],
    dependencies: [.package(path: "../../../../../mac/hmac-sha256/impl/swift/AbcHmacSha256Swift")],
    targets: [
        .target(name: "AbcHkdfSha256Swift", dependencies: [
            .product(name: "AbcHmacSha256Swift", package: "abchmacsha256swift"),
        ]),
        .testTarget(name: "AbcHkdfSha256SwiftTests", dependencies: ["AbcHkdfSha256Swift"]),
    ]
)

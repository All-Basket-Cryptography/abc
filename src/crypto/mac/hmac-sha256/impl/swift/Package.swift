// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcHmacSha256Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcHmacSha256Swift", targets: ["AbcHmacSha256Swift"])],
    dependencies: [.package(name: "AbcSha256Swift", path: "../../../../hash/sha256/impl/swift")],
    targets: [
        .target(name: "AbcHmacSha256Swift", dependencies: [
            .product(name: "AbcSha256Swift", package: "AbcSha256Swift"),
        ]),
        .testTarget(name: "AbcHmacSha256SwiftTests", dependencies: ["AbcHmacSha256Swift"]),
    ]
)

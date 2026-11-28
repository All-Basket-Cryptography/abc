// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcSha256Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcSha256Swift", targets: ["AbcSha256Swift"])],
    targets: [
        .target(name: "AbcSha256Swift"),
        .testTarget(name: "AbcSha256SwiftTests", dependencies: ["AbcSha256Swift"]),
    ]
)

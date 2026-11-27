// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AbcSha512Swift",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "AbcSha512Swift", targets: ["AbcSha512Swift"])],
    targets: [
        .target(name: "AbcSha512Swift"),
        .testTarget(name: "AbcSha512SwiftTests", dependencies: ["AbcSha512Swift"]),
    ]
)

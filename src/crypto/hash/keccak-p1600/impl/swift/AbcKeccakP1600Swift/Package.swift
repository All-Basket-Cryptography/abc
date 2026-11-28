// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcKeccakP1600Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcKeccakP1600Swift", targets: ["AbcKeccakP1600Swift"])],
    targets: [
        .target(name: "AbcKeccakP1600Swift"),
        .testTarget(name: "AbcKeccakP1600SwiftTests", dependencies: ["AbcKeccakP1600Swift"], resources: [.copy("oracle.json")]),
    ]
)

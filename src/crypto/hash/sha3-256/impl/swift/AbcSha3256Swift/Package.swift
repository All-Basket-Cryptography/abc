// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcSha3256Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcSha3256Swift", targets: ["AbcSha3256Swift"])],
    dependencies: [.package(path: "../../../../keccak-p1600/impl/swift/AbcKeccakP1600Swift")],
    targets: [
        .target(name: "AbcSha3256Swift", dependencies: [
            .product(name: "AbcKeccakP1600Swift", package: "abckeccakp1600swift"),
        ]),
        .testTarget(name: "AbcSha3256SwiftTests", dependencies: ["AbcSha3256Swift"], resources: [.copy("oracle.json")]),
    ]
)

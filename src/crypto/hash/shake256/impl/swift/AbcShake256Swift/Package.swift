// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcShake256Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcShake256Swift", targets: ["AbcShake256Swift"])],
    dependencies: [.package(path: "../../../../keccak-p1600/impl/swift/AbcKeccakP1600Swift")],
    targets: [
        .target(name: "AbcShake256Swift", dependencies: [
            .product(name: "AbcKeccakP1600Swift", package: "abckeccakp1600swift"),
        ]),
        .testTarget(name: "AbcShake256SwiftTests", dependencies: ["AbcShake256Swift"], resources: [.copy("oracle.json")]),
    ]
)

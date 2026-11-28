// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcEd25519Swift",
    platforms: [.macOS(.v15)],
    products: [.library(name: "AbcEd25519Swift", targets: ["AbcEd25519Swift"])],
    targets: [.target(name: "AbcEd25519Swift")]
)

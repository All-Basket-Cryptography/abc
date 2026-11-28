// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcX25519Swift",
    platforms: [.macOS(.v15)],
    products: [.library(name: "AbcX25519Swift", targets: ["AbcX25519Swift"])],
    targets: [.target(name: "AbcX25519Swift")]
)

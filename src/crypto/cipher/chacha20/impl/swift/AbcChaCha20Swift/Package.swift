// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcChaCha20Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcChaCha20Swift", targets: ["AbcChaCha20Swift"])],
    targets: [.target(name: "AbcChaCha20Swift")]
)

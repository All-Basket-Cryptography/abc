// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcAes256Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcAes256Swift", targets: ["AbcAes256Swift"])],
    targets: [.target(name: "AbcAes256Swift")]
)

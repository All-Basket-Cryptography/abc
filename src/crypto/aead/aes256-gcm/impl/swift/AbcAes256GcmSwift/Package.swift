// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcAes256GcmSwift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcAes256GcmSwift", targets: ["AbcAes256GcmSwift"])],
    targets: [.target(name: "AbcAes256GcmSwift")]
)

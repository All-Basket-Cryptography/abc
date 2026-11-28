// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AbcBlake2bSwift",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "AbcBlake2bSwift", targets: ["AbcBlake2bSwift"])],
    targets: [
        .target(name: "AbcBlake2bSwift"),
        .testTarget(name: "AbcBlake2bSwiftTests", dependencies: ["AbcBlake2bSwift"]),
    ]
)

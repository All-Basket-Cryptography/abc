// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcPoly1305Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcPoly1305Swift", targets: ["AbcPoly1305Swift"])],
    targets: [.target(name: "AbcPoly1305Swift")]
)

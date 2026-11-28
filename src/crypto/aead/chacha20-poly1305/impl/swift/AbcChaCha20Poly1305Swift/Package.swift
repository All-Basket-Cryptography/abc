// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcChaCha20Poly1305Swift",
    platforms: [.macOS(.v13)],
    products: [.library(name: "AbcChaCha20Poly1305Swift", targets: ["AbcChaCha20Poly1305Swift"])],
    dependencies: [.package(path: "../../../../../cipher/chacha20/impl/swift/AbcChaCha20Swift"), .package(path: "../../../../../mac/poly1305/impl/swift/AbcPoly1305Swift")],
    targets: [.target(name: "AbcChaCha20Poly1305Swift", dependencies: [.product(name: "AbcChaCha20Swift", package: "abcchacha20swift"), .product(name: "AbcPoly1305Swift", package: "abcpoly1305swift")])]
)

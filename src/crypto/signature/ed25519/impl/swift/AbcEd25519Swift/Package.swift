// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AbcEd25519Swift",
    platforms: [.macOS(.v15)],
    products: [.library(name: "AbcEd25519Swift", targets: ["AbcEd25519Swift"])],
    targets: [
        .systemLibrary(name: "CAbcEd25519OpenSSL", pkgConfig: "libcrypto", providers: [.brew(["openssl@3"])]),
        .target(name: "AbcEd25519Swift", dependencies: ["CAbcEd25519OpenSSL"]),
    ]
)

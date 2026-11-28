// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "AbcEcdsaP256Swift",
    platforms: [.macOS(.v15)],
    products: [.library(name: "AbcEcdsaP256Swift", targets: ["AbcEcdsaP256Swift"])],
    targets: [
        .systemLibrary(name: "CAbcEcdsaP256OpenSSL", pkgConfig: "libcrypto", providers: [.brew(["openssl@3"])]),
        .target(name: "AbcEcdsaP256Swift", dependencies: ["CAbcEcdsaP256OpenSSL"]),
    ]
)

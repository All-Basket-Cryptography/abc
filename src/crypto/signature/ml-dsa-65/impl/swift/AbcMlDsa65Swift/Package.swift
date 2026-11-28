// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "AbcMlDsa65Swift",
    platforms: [.macOS(.v15)],
    products: [.library(name: "AbcMlDsa65Swift", targets: ["AbcMlDsa65Swift"])],
    targets: [
        .systemLibrary(name: "CAbcMlDsa65OpenSSL", pkgConfig: "libcrypto", providers: [.brew(["openssl@3"])]),
        .target(name: "AbcMlDsa65Swift", dependencies: ["CAbcMlDsa65OpenSSL"]),
    ]
)

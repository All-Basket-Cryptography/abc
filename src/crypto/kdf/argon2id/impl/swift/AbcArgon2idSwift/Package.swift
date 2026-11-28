// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "AbcArgon2idSwift",
    platforms: [.macOS(.v15)],
    products: [.library(name: "AbcArgon2idSwift", targets: ["AbcArgon2idSwift"])],
    targets: [
        .systemLibrary(name: "CAbcArgon2idOpenSSL", pkgConfig: "libcrypto", providers: [.brew(["openssl@3"])]),
        .target(name: "AbcArgon2idSwift", dependencies: ["CAbcArgon2idOpenSSL"]),
    ]
)

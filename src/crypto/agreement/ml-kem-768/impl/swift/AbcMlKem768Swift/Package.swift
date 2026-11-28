// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "AbcMlKem768Swift",
    platforms: [.macOS(.v15)],
    products: [.library(name: "AbcMlKem768Swift", targets: ["AbcMlKem768Swift"])],
    targets: [
        .systemLibrary(name: "CAbcMlKem768OpenSSL", pkgConfig: "libcrypto", providers: [.brew(["openssl@3"])]),
        .target(name: "AbcMlKem768Swift", dependencies: ["CAbcMlKem768OpenSSL"]),
    ]
)

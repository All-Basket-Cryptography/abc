// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ABCCrypto",
    platforms: [.macOS(.v13)],
    products: [.library(name: "ABCCrypto", targets: ["ABCCrypto"])],
    targets: [
        .systemLibrary(name: "CABCCrypto", pkgConfig: "abc-crypto"),
        .target(name: "ABCCrypto", dependencies: ["CABCCrypto"]),
    ]
)

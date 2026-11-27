// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ABCExternalConsumer",
    platforms: [.macOS(.v13)],
    dependencies: [.package(name: "ABCCrypto", path: "../installed")],
    targets: [
        .executableTarget(name: "ABCExternalConsumer", dependencies: [
            .product(name: "ABCCrypto", package: "ABCCrypto"),
        ]),
    ]
)

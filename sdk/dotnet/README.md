# ABC SHA-256 for .NET

`Abc.Cryptography.Research` is a .NET 10 Windows x64 research package. Its native library is packaged as the `win-x64` runtime asset. It checks the C ABI version when initialized and exposes the actual provider identity. Bytes are read synchronously through `ReadOnlySpan<byte>`.

`Sha256.Digest` returns 32 bytes. `Sha256Stream.Update` accepts chunks, `Finish` closes the current operation, and `Reset` starts a new message. Dispose a stream when finished. The managed safe handle also releases an abandoned native context.

Use `python sdk/dotnet/package.py --dotnet /path/to/dotnet --output dist/dotnet` to build the Windows native library, create the NuGet package, restore it from a local feed in a clean project, and run the consumer. Platform and runtime expansion requires its own package and consumer evidence. [Official .NET release metadata](https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json)

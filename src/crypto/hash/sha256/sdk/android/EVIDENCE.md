# Android Kotlin research evidence

## Package and external consumer build

`python -B src/crypto/hash/sha256/sdk/android/package.py --consumer` completed on a Windows x64 host
on 2026-11-28 local time. The build used Rust 1.92.0, NDK 27.1.12297006 with
Clang 18.0.2, JDK 21.0.8, Gradle 8.13, Android Gradle Plugin 8.12.0, and Kotlin
2.1.20. Gradle compiled against Android API 36 and set the minimum API to 26.
The separate application assembled using the installed AAR in its `libs`
directory.

| Local artifact | SHA-256 |
| --- | --- |
| `dist/android/abc-android-0.1.0.aar` | `506353d97c689b256a6f14a2c26e5cdaa32317de7ff061ea0be76a152cccb273` |
| `dist/android/abc-android-consumer-debug.apk` | `96c41cf4c2fdc6ce360f378725fbb0ac78df9a164c759cc7710d7e9a586a848d` |

The AAR contains the shared Java JNI bridge and Kotlin facade. Each native
entry has the expected ELF64 machine value. The same library bytes are present
in the AAR and the consumer APK.

| ABI | ELF64 machine | Library SHA-256 |
| --- | --- | --- |
| `arm64-v8a` | 183 | `a4161e78d8e254f5e4df6ed2b58c20136d3932053883c08acc9030251f0611a8` |
| `x86_64` | 62 | `23a361ba9fc9c65a94f467b9de9cee695670086300a7bafacf1e32649efb321a` |

## Runtime verification

`python -B src/crypto/hash/sha256/sdk/android/emulator_test.py` installed and ran the exact consumer
APK in a fresh x86_64 Android API 36 virtual device. The app reported
`SHA-256 AAR consumer passed` after checking the NIST `abc` digest, provider
identity, split updates, reset, and closed and finalized state errors. The
script used an isolated ADB server and shut down the virtual device after
the run. ARM64 has compile-and-package evidence. Physical device and ARM64
runtime checks remain open.

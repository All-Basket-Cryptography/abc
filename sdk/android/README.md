# Android Kotlin SHA-256 research SDK

The Android archive exposes `org.allbasket.abc.android.Sha256`. It includes
JNI libraries for `arm64-v8a` and `x86_64` with an Android API 26 minimum.
The JNI entry points check the C ABI version and bind the existing Rust
SHA-256 provider. Kotlin `ByteArray` data remains caller-owned. Streaming
handles serialize operations through the shared Java bridge, can be reset
after finalization, and are released by `close()` or `use`.

The initial interface accepts public hashing inputs. Android Keystore,
non-exportable keys, and randomness need separate provider contracts.

Build the AAR and a separate Kotlin consumer APK with JDK 17+, Gradle 8.13,
Android platform 36, NDK 27.1.12297006 and Rust 1.92.0's two Android targets.
The Gradle build uses a populated dependency cache for Android Gradle Plugin
8.12.0 and Kotlin 2.1.20.

```sh
python sdk/android/package.py --consumer
python sdk/android/emulator_test.py
```

The consumer project links the exact AAR from its `libs` directory. The runtime
check creates its own Android API 36 virtual device and ADB server. It checks
the `abc` vector, split updates, provider identity, close, and reset.
Physical device runs and platform assurance are tracked separately.
[Android AAR format](https://developer.android.com/studio/projects/android-library)
[NDK toolchain targets](https://developer.android.com/ndk/guides/other_build_systems)

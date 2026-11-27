"""Build an Android research AAR and a clean Kotlin consumer APK."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "sdk/android"
JAVA_SOURCE = ROOT / "sdk/java/src"
JAVA_CLASS = JAVA_SOURCE / "org/allbasket/abc/Sha256.java"
NDK = "27.1.12297006"
GRADLE = "8.13"
RUST = "+1.92.0"
MIN_API = 26
ANDROID_ABIS = {"arm64-v8a": "aarch64-linux-android", "x86_64": "x86_64-linux-android"}
ARTIFACT = "abc-android-0.1.0.aar"


def run(command, env=None, timeout=180):
    print(subprocess.list2cmdline([str(arg) for arg in command]), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout, check=False)
    output = result.stdout + result.stderr
    print(output, flush=True)
    result.check_returncode()
    return output


def default_sdk():
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if value := os.environ.get(key):
            return Path(value)
    if os.name == "nt":
        local_roots = (os.environ.get("LOCALAPPDATA"), Path.home() / "AppData/Local")
        for local in local_roots:
            if local and (candidate := Path(local) / "Android/Sdk").is_dir():
                return candidate
    return None


def default_jdk():
    if value := os.environ.get("JAVA_HOME"):
        return Path(value)
    if programs := os.environ.get("ProgramFiles"):
        studio = Path(programs) / "Android/Android Studio/jbr"
        if studio.is_dir():
            return studio
    return None


def default_gradle():
    if value := os.environ.get("GRADLE_HOME"):
        return Path(value)
    wrapper = Path.home() / ".gradle/wrapper/dists"
    installed = sorted(wrapper.glob(f"gradle-{GRADLE}-*/*/gradle-{GRADLE}"))
    return installed[0] if installed else None


def required_file(path):
    if not path.is_file():
        raise ValueError(f"required file is unavailable: {path}")
    return path


def tool_home(sdk, jdk, gradle):
    host_tag = {"Windows": "windows-x86_64", "Linux": "linux-x86_64", "Darwin": "darwin-x86_64"}.get(platform.system())
    if not host_tag:
        raise ValueError(f"unsupported NDK host: {platform.system()}")
    required_file(sdk / "platforms/android-36/android.jar")
    suffix = ".exe" if os.name == "nt" else ""
    ndk = sdk / "ndk" / NDK / "toolchains/llvm/prebuilt" / host_tag / "bin"
    clang = required_file(ndk / f"clang{suffix}")
    java = required_file(jdk / "bin" / f"java{suffix}")
    javac = required_file(jdk / "bin" / f"javac{suffix}")
    launcher = required_file(gradle / "lib" / f"gradle-gradle-cli-main-{GRADLE}.jar")
    return clang, java, javac, launcher


def native_libraries(work, clang, javac):
    headers = work / "headers"
    classes = work / "java-classes"
    headers.mkdir()
    classes.mkdir()
    run([javac, "--release", "17", "-h", headers, "-d", classes, JAVA_CLASS])
    directory = work / "native"
    target_dir = work / "cargo-target"
    for abi, target in ANDROID_ABIS.items():
        compiler_argument = f"--target={target}{MIN_API}"
        env = dict(os.environ)
        env.pop("RUSTFLAGS", None)
        env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        rust_env = target.upper().replace("-", "_")
        env[f"CARGO_TARGET_{rust_env}_LINKER"] = str(clang)
        env[f"CARGO_TARGET_{rust_env}_RUSTFLAGS"] = f"-C link-arg={compiler_argument}"
        output = run(["cargo", RUST, "rustc", "--manifest-path", ROOT / "build/rust/Cargo.toml",
                      "--locked", "--offline", "--release", "-p", "abc-c-ffi",
                      "--target", target, "--target-dir", target_dir, "--", "--print", "native-static-libs"], env)
        match = re.search(r"native-static-libs: ([^\r\n]+)", output)
        libraries = match[1].split() if match else []
        if not libraries or not all(re.fullmatch(r"-l[a-zA-Z0-9_]+", name) for name in libraries):
            raise RuntimeError(f"Rust did not report supported Android native link libraries for {target}")
        abi_dir = directory / abi
        abi_dir.mkdir(parents=True)
        archive = required_file(target_dir / target / "release/libabc_crypto.a")
        run([clang, compiler_argument, "-fPIC", "-fvisibility=hidden", "-shared", "-Wl,--exclude-libs,ALL",
             "-Wl,-z,max-page-size=16384", "-Wl,-soname,libabc_android.so", "-I", headers,
             "-I", ROOT / "sdk/c/include", ROOT / "sdk/java/jni/sha256.c", archive, *libraries,
             "-o", abi_dir / "libabc_android.so"])
    return directory


def build_gradle(java, jar, project, environment, *args):
    run([java, "-classpath", jar, "org.gradle.launcher.GradleMain", "--offline", "--no-daemon", "--console=plain",
         "--max-workers=2", "-Dorg.gradle.vfs.watch=false", "-Pkotlin.compiler.execution.strategy=in-process",
         "-p", project, *args], environment, timeout=360)


def package(args):
    sdk, jdk, gradle = (value.resolve() for value in (args.sdk, args.jdk, args.gradle))
    clang, java, javac, launcher = tool_home(sdk, jdk, gradle)
    run([clang, "--version"])
    run([java, "-version"])
    cache = ROOT / ".abc/android"
    cache.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    java_home = cache / "java-home"
    java_home.mkdir(exist_ok=True)
    gradle_cache = args.gradle_cache.resolve()
    gradle_cache.mkdir(parents=True, exist_ok=True)
    environment = {**os.environ, "ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": str(sdk), "JAVA_HOME": str(jdk),
                   "ANDROID_USER_HOME": str(java_home), "GRADLE_USER_HOME": str(gradle_cache)}
    if args.dependency_cache:
        shared_cache = args.dependency_cache.resolve()
        environment["GRADLE_RO_DEP_CACHE"] = str(shared_cache.parent if shared_cache.name == "modules-2" else shared_cache)
    with tempfile.TemporaryDirectory(prefix="build-", dir=cache) as temp:
        work = Path(temp)
        native = native_libraries(work, clang, javac)
        project = work / "library"
        for name in ("settings.gradle", "build.gradle", "consumer-rules.pro"):
            project.mkdir(exist_ok=True)
            shutil.copyfile(SOURCE / name, project / name)
        shutil.copytree(SOURCE / "src", project / "src")
        build_gradle(java, launcher, project, environment, "assembleRelease", f"-PabcJavaSource={JAVA_SOURCE}",
                     f"-PabcNativeDir={native}")
        library = required_file(project / "build/outputs/aar/abc-android-release.aar")
        with ZipFile(library) as archive:
            entries = {"AndroidManifest.xml", "classes.jar"} | {f"jni/{abi}/libabc_android.so" for abi in ANDROID_ABIS}
            if not entries <= set(archive.namelist()):
                raise RuntimeError("Android archive is missing class or ABI entries")
        artifact = output / ARTIFACT
        shutil.copyfile(library, artifact)
        artifacts = [artifact]
        if args.consumer:
            consumer = work / "consumer"
            shutil.copytree(SOURCE / "consumer", consumer)
            (consumer / "libs").mkdir()
            shutil.copyfile(artifact, consumer / "libs" / ARTIFACT)
            build_gradle(java, launcher, consumer, environment, "assembleDebug")
            apk = required_file(consumer / "build/outputs/apk/debug/abc-android-consumer-debug.apk")
            installed = output / apk.name
            shutil.copyfile(apk, installed)
            artifacts.append(installed)
    return {"profile": "research", "min_sdk": MIN_API, "ndk": NDK, "gradle": GRADLE, "abis": sorted(ANDROID_ABIS),
            "consumer_compiled": args.consumer,
            "artifacts": {file.name: sha256(file.read_bytes()).hexdigest() for file in artifacts}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, default=default_sdk())
    parser.add_argument("--jdk", type=Path, default=default_jdk())
    parser.add_argument("--gradle", type=Path, default=default_gradle())
    parser.add_argument("--gradle-cache", type=Path, default=ROOT / ".abc/android/gradle")
    host_dependency_cache = Path.home() / ".gradle/caches"
    parser.add_argument("--dependency-cache", type=Path,
                        default=host_dependency_cache if (host_dependency_cache / "modules-2").is_dir() else None)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/android")
    parser.add_argument("--consumer", action="store_true")
    args = parser.parse_args()
    if not all((args.sdk, args.jdk, args.gradle)):
        parser.error("provide an Android SDK, JDK 17+, and Gradle 8.13 using --sdk, --jdk, and --gradle")
    try:
        encoded = json.dumps(package(args), indent=2) + "\n"
        if output := os.environ.get("ABC_TASK_OUTPUT"):
            (Path(output) / "android-artifacts.json").write_text(encoded, encoding="utf-8", newline="\n")
        print(encoded, flush=True)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Android packaging failed: {error}\n")


if __name__ == "__main__":
    main()

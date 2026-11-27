"""Build and check the classifier-specific Windows JNI research package."""

import os
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from tools.abc_go import _require_windows
from tools.abc_package import RUST_CHANNEL, RUST_MANIFEST, _metadata, _run


ARTIFACT = "abc-sha256-0.1.0-windows-amd64.jar"


def _jdk():
    home = os.environ.get("ABC_JAVA_HOME") or os.environ.get("JAVA_HOME")
    if home is None:
        raise ValueError("Set ABC_JAVA_HOME or JAVA_HOME to a Windows amd64 JDK 17 installation")
    location = Path(home).resolve()
    if not (location / "include/jni.h").is_file():
        raise ValueError("The selected Java home does not include JNI development headers")
    return location


def _compile_java(repo, compiler, classes, additional=()):
    _run([str(compiler), "--release", "17", *additional, "-d", str(classes),
          str(repo / "sdk/java/src/org/allbasket/abc/Sha256.java")], classes)


def package_java(repo, directory):
    _require_windows()
    jdk = _jdk()
    output = directory.resolve()
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / ARTIFACT
    _run(["cargo", f"+{RUST_CHANNEL}", "build", "--manifest-path", RUST_MANIFEST, "--target-dir", "target",
          "--locked", "--offline", "-p", "abc-c-ffi", "--release"], repo)
    with TemporaryDirectory(prefix="abc-java-") as location:
        stage = Path(location)
        classes = stage / "classes"
        headers = stage / "headers"
        native = classes / "native/windows-amd64"
        native.mkdir(parents=True)
        headers.mkdir()
        _compile_java(repo, jdk / "bin/javac.exe", classes, ("-h", str(headers)))
        _run(["clang", "-shared", "-std=c17", "-Wall", "-Wextra", "-Werror", "-fms-runtime-lib=static", "-DABC_CRYPTO_SHARED",
              "-I", str(headers), "-I", str(jdk / "include"), "-I", str(jdk / "include/win32"), "-I", str(repo / "sdk/c/include"),
              str(repo / "sdk/java/jni/sha256.c"), str(repo / "target/release/abc_crypto.dll.lib"),
              "-o", str(native / "abc_java.dll")], stage)
        shutil.copyfile(repo / "target/release/abc_crypto.dll", native / "abc_crypto.dll")
        # Linkers also emit import libraries. The runtime JAR only needs the two DLLs.
        for file in native.iterdir():
            if file.suffix != ".dll":
                file.unlink()
        maven = classes / "META-INF/maven/org.allbasket/abc-sha256"
        maven.mkdir(parents=True)
        shutil.copyfile(repo / "sdk/java/pom.xml", maven / "pom.xml")
        _run([str(jdk / "bin/jar.exe"), "--create", "--date=2000-01-01T00:00:00Z", "--file", str(artifact),
              "-C", str(classes), "."], stage)
    shutil.copyfile(repo / "sdk/java/pom.xml", output / "abc-sha256-0.1.0.pom")
    return {"profile": "research", "sdk": "java", **_metadata(artifact)}


def check_java(repo, artifact):
    _require_windows()
    jdk = _jdk()
    path = artifact.resolve(strict=True)
    with ZipFile(path) as distribution:
        expected = {"native/windows-amd64/abc_crypto.dll", "native/windows-amd64/abc_java.dll",
                    "org/allbasket/abc/Sha256.class", "META-INF/maven/org.allbasket/abc-sha256/pom.xml", "META-INF/MANIFEST.MF"}
        if {name for name in distribution.namelist() if not name.endswith("/")} != expected:
            raise ValueError("JVM archive is missing a required class, POM or library")
    with TemporaryDirectory(prefix="abc-java-consumer-") as location:
        project = Path(location)
        shutil.copyfile(repo / "compatibility/consumers/java/Consumer.java", project / "Consumer.java")
        _run([str(jdk / "bin/javac.exe"), "--release", "17", "-cp", str(path), "Consumer.java"], project)
        result = _run([str(jdk / "bin/java.exe"), "-Xcheck:jni", "-cp", os.pathsep.join([str(path), "."]), "Consumer"], project).strip()
        message = "External Java SHA-256 consumer passed"
        if not result.endswith(message):
            raise ValueError("Java consumer did not report success")
        warnings = [line for line in result.splitlines() if line.startswith("WARNING")]
    return {"profile": "research", "sdk": "java", **_metadata(path), "checks": {"java": message}, "jvm_warnings": warnings}


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[1]
    try:
        compiler = _jdk() / "bin/javac.exe" if os.name == "nt" else "javac"
        with TemporaryDirectory(prefix="abc-java-check-") as location:
            _compile_java(repo, compiler, Path(location))
        print("Java source compiled for JDK 17")
    except (OSError, ValueError) as failure:
        sys.exit(str(failure))

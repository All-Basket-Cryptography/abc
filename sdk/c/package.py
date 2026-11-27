"""Build native research archives and verify clean CMake consumers."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[2]
C_SDK = ROOT / "sdk/c"
CPP_SDK = ROOT / "sdk/cpp"
VERSION = tomllib.loads((C_SDK / "ffi/Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
HOSTS = {"x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"}
TOOLCHAIN = "+1.92.0"
WINDOWS = "x86_64-pc-windows-msvc"


def run(command):
    result = subprocess.run(command, cwd=ROOT, text=True, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, check=False)
    print(f"{subprocess.list2cmdline([str(arg) for arg in command])}\n{result.stdout}", flush=True)
    result.check_returncode()
    return result.stdout


def tool(name):
    executable = shutil.which(name)
    if executable:
        return Path(executable)
    if os.name == "nt" and name in {"cmake", "ctest", "ninja"}:
        for key in ("ProgramFiles", "ProgramFiles(x86)"):
            directory = os.environ.get(key)
            if not directory:
                continue
            suffix = "Ninja/ninja.exe" if name == "ninja" else f"CMake/bin/{name}.exe"
            pattern = f"Microsoft Visual Studio/*/*/Common7/IDE/CommonExtensions/Microsoft/CMake/{suffix}"
            matches = sorted(Path(directory).glob(pattern))
            if matches:
                return matches[-1]
    raise RuntimeError(f"required tool is unavailable: {name}")


def native_files(target, directory):
    names = (("abc_crypto.lib", "abc_crypto.dll.lib", "abc_crypto.dll") if target == WINDOWS
             else ("libabc_crypto.a", "libabc_crypto.so"))
    paths = [directory / name for name in names]
    if not all(item.is_file() for item in paths):
        raise RuntimeError(f"native build did not produce all expected library files: {paths}")
    return paths


def assert_exports(target, library):
    expected = set((C_SDK / "abi-v1-symbols.txt").read_text(encoding="utf-8").split())
    if target == WINDOWS:
        text = run([tool("llvm-readobj"), "--coff-exports", library])
        actual = set(re.findall(r"\bName:\s+(abc_\w+)\b", text))
    else:
        text = run([tool("nm"), "-D", "--defined-only", library])
        actual = set(re.findall(r"\b(abc_\w+)$", text, re.MULTILINE))
    if expected != actual:
        raise RuntimeError(f"ABI v1 export change: missing {sorted(expected - actual)}, extra {sorted(actual - expected)}")


def write_file(directory, relative, text):
    path = directory / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_config(stage, name, template, variables):
    text = template.read_text(encoding="utf-8")
    for placeholder, value in variables.items():
        text = text.replace(f"@{placeholder}@", value)
    base = f"lib/cmake/{name}/{name}Config"
    write_file(stage, f"{base}.cmake", text)
    write_file(stage, f"{base}Version.cmake", f'''set(PACKAGE_VERSION "{VERSION}")
if(PACKAGE_FIND_VERSION_MAJOR EQUAL 0 AND NOT PACKAGE_FIND_VERSION VERSION_GREATER PACKAGE_VERSION)
    set(PACKAGE_VERSION_COMPATIBLE TRUE)
endif()
if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
    set(PACKAGE_VERSION_EXACT TRUE)
endif()
''')


def prepare_c(work, target, stage):
    target_dir = work / "cargo-target"
    output = run(["cargo", TOOLCHAIN, "rustc", "--locked", "--offline", "--release", "-p", "abc-c-ffi",
                  "--target", target, "--target-dir", target_dir, "--", "--print", "native-static-libs"])
    matches = re.findall(r"native-static-libs: (.+)", output)
    if len(matches) != 1:
        raise RuntimeError("Rust did not report the native static link dependencies")
    link_libraries = [item.removeprefix("/defaultlib:") + ".lib" if item.startswith("/defaultlib:") else item
                      for item in matches[0].split()]
    if not all(re.fullmatch(r"(?:-l)?[a-zA-Z0-9_.-]+", library) for library in link_libraries):
        raise RuntimeError("unexpected native static linker argument")
    files = native_files(target, target_dir / target / "release")
    assert_exports(target, files[-1])
    shutil.copytree(C_SDK / "include", stage / "include")
    shutil.copyfile(C_SDK / "README.md", stage / "README-C.md")
    shutil.copyfile(C_SDK / "abi-v1-symbols.txt", stage / "abi-v1-symbols.txt")
    (stage / "lib").mkdir()
    for path in files:
        folder = "bin" if path.suffix == ".dll" else "lib"
        destination = stage / folder / path.name
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(path, destination)
    write_config(stage, "ABCCrypto", C_SDK / "ABCCryptoConfig.cmake.in", {
        "NATIVE_LIBS": ";".join(link_libraries), "STATIC": files[0].name,
        "SHARED": f"{'bin' if target == WINDOWS else 'lib'}/{files[-1].name}",
        "IMPORT_LIB": files[1].name if target == WINDOWS else "",
    })


def prepare_cpp(stage):
    shutil.copytree(CPP_SDK / "include", stage / "include")
    shutil.copyfile(CPP_SDK / "README.md", stage / "README-Cpp.md")
    write_config(stage, "ABCCryptoCpp", CPP_SDK / "ABCCryptoCppConfig.cmake.in", {})


def archive(stage, path):
    with tempfile.NamedTemporaryFile(dir=path.parent, suffix=".tmp", delete=False) as file:
        temporary = Path(file.name)
    try:
        with ZipFile(temporary, "w", compression=ZIP_DEFLATED) as output:
            for entry in sorted(stage.rglob("*")):
                if entry.is_file():
                    output.write(entry, entry.relative_to(stage).as_posix())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Built {path}", flush=True)


def consumer(work, sdk, packages):
    install = work / "installed"
    for archive_path in packages:
        with ZipFile(archive_path) as archive_file:
            archive_file.extractall(install)
    source = work / f"consumer-{sdk}"
    shutil.copytree((CPP_SDK if sdk == "cpp" else C_SDK) / "consumer", source)
    build = work / f"cmake-{sdk}"
    cmake, ctest = tool("cmake"), tool("ctest")
    config = [cmake, "-S", source, "-B", build, f"-DCMAKE_PREFIX_PATH={install}", "-DCMAKE_BUILD_TYPE=Release"]
    if os.name == "nt":
        try:
            ninja = tool("ninja")
            compiler = tool("clang++" if sdk == "cpp" else "clang")
        except RuntimeError:
            os.environ["MSBUILDDISABLENODEREUSE"] = "1"
        else:
            language = "CXX" if sdk == "cpp" else "C"
            config.extend(["-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={ninja}", f"-DCMAKE_{language}_COMPILER={compiler}"])
    run(config)
    run([cmake, "--build", build, "--config", "Release", "--parallel", "2"])
    run([ctest, "--test-dir", build, "-C", "Release", "--output-on-failure"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", choices=("c", "cpp"), required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--consumer", action="store_true")
    args = parser.parse_args()
    fingerprint = run(["rustc", TOOLCHAIN, "--version", "--verbose"])
    host = re.search(r"^host: (\S+)$", fingerprint, re.MULTILINE).group(1)
    if host not in HOSTS:
        raise RuntimeError(f"unsupported research package target: {host}")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="abc-native-", ignore_cleanup_errors=os.name == "nt") as temp:
        work = Path(temp)
        c_stage = work / "c-stage"
        prepare_c(work, host, c_stage)
        package = args.output / f"abc-c-{VERSION}-{host}.zip"
        archive(c_stage, package)
        packages = [package]
        if args.sdk == "cpp":
            cpp_stage = work / "cpp-stage"
            prepare_cpp(cpp_stage)
            package = args.output / f"abc-cpp-{VERSION}-{host}.zip"
            archive(cpp_stage, package)
            packages.append(package)
        if args.consumer:
            consumer(work, "c", packages[:1])
            if args.sdk == "cpp":
                consumer(work, "cpp", packages)
        manifest = {"target": host, "abi": 65536, "consumer_tests_run": args.consumer,
                    "archives": {item.name: hashlib.sha256(item.read_bytes()).hexdigest() for item in packages}}
        if output := os.environ.get("ABC_TASK_OUTPUT"):
            write_file(Path(output), "archive-sha256.json", json.dumps(manifest, indent=2) + "\n")
        print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()

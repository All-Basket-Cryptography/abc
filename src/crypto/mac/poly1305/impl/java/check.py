"""Compile the Java Poly1305 JAR and compare an independent consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "src/org/allbasket/abc/mac/poly1305/Poly1305.java"
TEST = HERE / "tests/Checks.java"
LENGTHS = (*range(41), 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1025, 4097)


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{stdout}{stderr}")
    return result.stdout.decode("utf-8").strip(), result.stderr.decode("utf-8").strip()


def executable(jdk, name):
    binary = name + (".exe" if os.name == "nt" else "")
    return str(jdk.resolve() / "bin" / binary) if jdk else binary


def oracle(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    h = 0
    for offset in range(0, len(message), 16):
        block = int.from_bytes(message[offset:offset + 16] + b"\x01", "little")
        h = (h + block) * r % ((1 << 130) - 5)
    return ((h + s) % (1 << 128)).to_bytes(16, "little")


def vectors():
    def block(first, rest=0):
        return bytes([first, *([rest] * 15)])

    yield (bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
           bytes.fromhex("43727970746f6772617068696320466f72756d2052657365617263682047726f7570"),
           bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9"))

    zero, one, two, ones = bytes(16), block(1), block(2), block(255, 255)
    wide_r = bytes.fromhex("01000000000000000400000000000000")
    wide_message = bytes.fromhex("e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000")
    yield two + zero, ones, block(3)
    yield two + ones, two, block(3)
    yield one + zero, ones + block(0xf0, 255) + block(17), block(5)
    yield one + zero, ones + block(0xfb, 0xfe) + block(1, 1), zero
    yield two + zero, block(0xfd, 255), block(0xfa, 255)
    yield wide_r + zero, wide_message + zero + one, bytes.fromhex("14000000000000005500000000000000")
    yield wide_r + zero, wide_message + zero, block(0x13)


def fixtures():
    cases = []
    for key, message, expected in vectors():
        if oracle(key, message) != expected:
            raise ValueError("Integer oracle disagrees with RFC 8439")
        cases.append((key, message, expected, True))
    rng = random.Random(84391305)
    for length in LENGTHS:
        for key, message in (
            (rng.randbytes(32), rng.randbytes(length)),
            (b"\xff" * 32, b"\xff" * length),
            (bytes(16) + b"\xa5" * 16, b"\x55" * length),
        ):
            cases.append((key, message, oracle(key, message), length <= 257))
    for _ in range(256):
        key, message = rng.randbytes(32), rng.randbytes(rng.randrange(1025))
        cases.append((key, message, oracle(key, message), False))
    return cases


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--openssl", type=Path, help="also compare selected cases with this OpenSSL CLI")
    parser.add_argument("--output", type=Path, help="retain the tested JAR and receipt")
    options = parser.parse_args()
    java, javac, jar = (executable(options.jdk, name) for name in ("java", "javac", "jar"))
    stdout, stderr = run([java, "-version"])
    version = stdout or stderr
    if not re.search(r'version "17(?:\.|")', version):
        raise ValueError(f"Expected JDK 17, got {version}")
    cases = fixtures()
    selected_openssl = 0
    openssl = None
    if options.openssl:
        cli = str(options.openssl.resolve())
        openssl, _ = run([cli, "version"])
        for key, message, expected, _ in cases[:8] + cases[8::13]:
            observed, _ = run([cli, "mac", "-macopt", "hexkey:" + key.hex(), "POLY1305"], input=message)
            if bytes.fromhex(observed) != expected:
                raise ValueError("Independent OpenSSL Poly1305 tag mismatch")
            selected_openssl += 1
    splits = sum(len(message) + 1 for _, message, _, all_splits in cases if all_splits)
    inputs = "".join(
        f"{key.hex()}:{message.hex()}:{expected.hex()}:{'all' if all_splits else 'sample'}\n"
        for key, message, expected, all_splits in cases
    ).encode("ascii")

    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-poly1305-java-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        classes, consumer = work / "classes", work / "consumer"
        classes.mkdir()
        consumer.mkdir()
        artifact = work / "abc-poly1305.jar"
        flags = ["--release", "17", "-Xlint:all", "-Werror"]
        run([javac, *flags, "-d", str(classes), str(SOURCE)])
        run([jar, "--create", "--file", str(artifact), "--date", "2000-01-01T00:00:00Z",
             "-C", str(classes), "."])
        run([javac, *flags, "-classpath", str(artifact), "-d", str(consumer), str(TEST)])
        observed, _ = run([java, "-classpath", os.pathsep.join(map(str, (artifact, consumer))), "Checks"],
                          cwd=work, input=inputs)
        checks = dict(line.split("=", 1) for line in observed.splitlines())
        if checks != {"cases": str(len(cases)), "splits": str(splits)}:
            raise ValueError(f"The consumer reported unexpected conformance counts: {checks}")
        report = {
            "status": "passed",
            "jdk": version,
            "python": platform.python_version(),
            "openssl": openssl,
            "checks": {**checks, "rfc": 8, "openssl": selected_openssl},
            "source_sha256": fingerprint(SOURCE),
            "test_sha256": fingerprint(TEST),
            "artifact_sha256": fingerprint(artifact),
        }
        if options.output:
            output = options.output.resolve()
            output.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(artifact, output / artifact.name)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

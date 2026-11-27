"""Differentially test Rust against the RFC 8439 integer construction."""
from pathlib import Path
from random import Random
import subprocess


def reference(key, message):
    multiplier = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    offset = int.from_bytes(key[16:], "little")
    prime = (1 << 130) - 5
    acc = 0
    for i in range(0, len(message), 16):
        n = int.from_bytes(message[i:i + 16] + b"\x01", "little")
        acc = ((acc + n) * multiplier) % prime
    return ((acc + offset) % (1 << 128)).to_bytes(16, "little").hex()


def main():
    rng = Random(8439)
    sizes = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 256, 257, 4096]
    cases = []
    for size in sizes:
        cases.extend((key, message) for key in (bytes(32), bytes([255]) * 32, rng.randbytes(32))
                     for message in (bytes(size), bytes([255]) * size, rng.randbytes(size)))
    cases.extend((rng.randbytes(32), rng.randbytes(rng.randrange(2049))) for _ in range(2000))
    repo = Path(__file__).resolve().parents[5]
    command = ["cargo", "+1.92.0", "run", "--release", "--quiet", "--offline", "--locked",
               "--manifest-path", "tools/build/rust/Cargo.toml", "-p", "abc-poly1305",
               "--example", "poly1305_differential"]
    vectors = "".join(f"{key.hex()}:{message.hex()}\n" for key, message in cases)
    result = subprocess.run(command, cwd=repo, input=vectors, capture_output=True, text=True, check=True, timeout=120)
    tags = result.stdout.splitlines()
    if len(tags) != len(cases):
        raise ValueError(f"Expected {len(cases)} results, received {len(tags)}")
    for index, ((key, message), tag) in enumerate(zip(cases, tags, strict=True)):
        if tag != reference(key, message):
            raise ValueError(f"Poly1305 mismatch for case {index}, length {len(message)}")
    print(f"Poly1305 matched the integer oracle for {len(cases)} cases")


if __name__ == "__main__":
    main()

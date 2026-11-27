"""Compare an ABC scrypt implementation against Python's OpenSSL scrypt."""
import argparse
import hashlib
from pathlib import Path
from random import Random
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--implementation", choices=["rust", "go"], default="rust")
    options = parser.parse_args()
    rng = Random(7914)
    cases = []
    for n in [16, 32, 128, 512]:
        for block_size in [1, 2, 4, 8]:
            for parallel in [1, 2, 3]:
                for length in [1, 33, 64]:
                    password = rng.randbytes(rng.choice([0, 31, 64, 65, 133, 4096]))
                    salt = rng.randbytes(rng.choice([0, 16, 64, 129]))
                    cases.append((password, salt, n, block_size, parallel, length))
    repo = Path(__file__).resolve().parents[5]
    if options.implementation == "go":
        command = ["go", "run", "-C", "src/crypto/kdf/scrypt/impl/go", "./cmd/corpus"]
    else:
        command = ["cargo", "+1.92.0", "run", "--release", "--quiet", "--locked", "--offline",
                   "--manifest-path", "tools/build/rust/Cargo.toml", "-p", "abc-scrypt", "--example", "scrypt_differential"]
    encoded = "".join(f"{pw.hex()}:{salt.hex()}:{n}:{r}:{p}:{length}\n" for pw, salt, n, r, p, length in cases)
    run = subprocess.run(command, cwd=repo, check=True, timeout=110, text=True, input=encoded, capture_output=True)
    outputs = run.stdout.splitlines()
    if len(outputs) != len(cases):
        raise ValueError(f"Expected {len(cases)} scrypt outputs, got {len(outputs)}")
    for index, ((pw, salt, n, r, p, length), result) in enumerate(zip(cases, outputs, strict=True)):
        expected = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=length)
        if result != expected.hex():
            raise ValueError(f"scrypt mismatch in case {index}, N={n}, r={r}, p={p}, dkLen={length}")
    print(f"scrypt matched the OpenSSL oracle for {len(cases)} cases")


if __name__ == "__main__":
    main()

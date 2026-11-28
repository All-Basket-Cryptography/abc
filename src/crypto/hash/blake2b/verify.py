"""Compare portable BLAKE2b outputs to Python's hashlib."""

from hashlib import blake2b
from pathlib import Path
from subprocess import check_output


def main():
    repo = Path(__file__).resolve().parents[4]
    raw = check_output(
        ["cargo", "+1.92.0", "run", "--locked", "--offline", "--quiet",
         "--manifest-path", "tools/build/rust/Cargo.toml", "-p", "abc-blake2b", "--example", "differential"],
        cwd=repo,
        encoding="ascii",
        timeout=120,
    )
    lengths = (0, 1, 127, 128, 129, 255, 256, 257, 512)
    expected_cases = {(size, length) for size in range(1, 65) for length in lengths}
    for line in raw.splitlines():
        raw_size, raw_length, digest = line.split("\t")
        size, length = int(raw_size), int(raw_length)
        expected_cases.remove((size, length))
        data = bytes((37 * i + 11) % 256 for i in range(length))
        if digest != blake2b(data, digest_size=size).hexdigest():
            raise ValueError(f"BLAKE2b mismatch at input length {length} and digest size {size}")
    if expected_cases:
        raise ValueError(f"missing {len(expected_cases)} differential cases")
    print("BLAKE2b passed 576 one-shot and streaming comparisons against hashlib")


if __name__ == "__main__":
    main()

"""Build the shared Lean module and check an independent specification."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FOUNDATION = ROOT / "foundation/lean"
PIN = (FOUNDATION / "lean-toolchain").read_text(encoding="utf-8").strip()


def checked_lean(command, arguments, directory, output):
    args = [*command, f"--root={directory}", *arguments]
    env = {**os.environ, "LEAN_PATH": str(output)}
    subprocess.run(args, cwd=directory, env=env, check=True, timeout=90)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", choices=("foundation", "sha256", "sha3"))
    selected = parser.parse_args().module
    elan, lean = shutil.which("elan"), shutil.which("lean")
    if elan:
        command = [elan, "run", PIN, "lean"]
    elif lean:
        version = subprocess.check_output([lean, "--version"], text=True, timeout=15)
        if f"version {PIN.split(':v')[1]}" not in version:
            parser.exit(1, f"Lean toolchain mismatch: expected {PIN}; found {version.strip()}\n")
        command = [lean]
    else:
        parser.exit(1, f"Lean toolchain unavailable: {PIN}\n")

    with tempfile.TemporaryDirectory(prefix="abc-lean-spec-") as temporary:
        output = Path(temporary)
        compiled = output / "Abc/Foundation/Encoding.olean"
        compiled.parent.mkdir(parents=True)
        checked_lean(command, ["-o", compiled, "Abc/Foundation/Encoding.lean"], FOUNDATION, output)
        if selected == "sha256":
            directory = ROOT / "algorithms/hash/sha2/sha256/formal"
            checked_lean(command, ["-o", output / "Sha256Spec.olean", "Sha256Spec.lean"], directory, output)
            for module in ("CompressionRefinement", "StreamingRefinement"):
                checked_lean(command, ["-o", output / f"{module}.olean", f"{module}.lean"], directory, output)
            checked_lean(command, ["--run", "Checks.lean"], directory, output)
        elif selected == "sha3":
            directory = ROOT / "algorithms/hash/sha3/sha3-256/formal"
            checked_lean(command, ["Sha3Encoding.lean"], directory, output)


if __name__ == "__main__":
    main()

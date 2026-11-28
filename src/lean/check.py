"""Build the shared Lean module and check an independent specification."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FOUNDATION = ROOT / "src/lean"
PIN = (FOUNDATION / "lean-toolchain").read_text(encoding="utf-8").strip()


def checked_lean(command, arguments, directory, output):
    args = [*command, f"--root={directory}", *arguments]
    env = {**os.environ, "LEAN_PATH": str(output)}
    subprocess.run(args, cwd=directory, env=env, check=True, timeout=90)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", choices=(
        "foundation", "sha256", "sha512", "sha3", "shake256", "keccak-reader", "hmac", "hkdf", "pbkdf2", "chacha20",
        "poly1305",
    ))
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
        if selected in ("sha256", "hmac", "hkdf", "pbkdf2"):
            directory = ROOT / "src/crypto/hash/sha256/spec"
            checked_lean(command, ["-o", output / "Sha256Spec.olean", "Sha256Spec.lean"], directory, output)
        if selected in ("sha256", "hmac"):
            for module in ("CompressionRefinement", "StreamingRefinement"):
                checked_lean(command, ["-o", output / f"{module}.olean", f"{module}.lean"], directory, output)
        if selected == "sha256":
            checked_lean(command, ["--run", "Checks.lean"], directory, output)
        elif selected == "sha3":
            directory = ROOT / "src/crypto/hash/sha3-256/spec"
            checked_lean(command, ["Sha3Encoding.lean"], directory, output)
        elif selected == "sha512":
            directory = ROOT / "src/crypto/hash/sha512/spec"
            checked_lean(command, ["Sha512Length.lean"], directory, output)
        elif selected == "shake256":
            directory = ROOT / "src/crypto/hash/shake256/spec"
            checked_lean(command, ["Shake256Encoding.lean"], directory, output)
        elif selected == "keccak-reader":
            directory = ROOT / "src/crypto/hash/keccak-p1600/spec"
            for module in ("KeccakRound", "KeccakReader"):
                checked_lean(command, ["-DwarningAsError=true", "-o", output / f"{module}.olean",
                                       f"{module}.lean"], directory, output)
            checked_lean(command, ["-DwarningAsError=true", "KeccakSpongeRead.lean"], directory, output)
        if selected in ("hmac", "hkdf", "pbkdf2"):
            directory = ROOT / "src/crypto/mac/hmac-sha256/spec"
            checked_lean(command, ["-o", output / "HmacSpec.olean", "HmacSpec.lean"], directory, output)
        if selected == "hmac":
            checked_lean(command, ["-DwarningAsError=true", "HmacPrepared.lean"], directory, output)
        if selected == "hkdf":
            directory = ROOT / "src/crypto/kdf/hkdf-sha256/spec"
            checked_lean(command, ["HkdfSpec.lean"], directory, output)
        if selected == "pbkdf2":
            directory = ROOT / "src/crypto/kdf/pbkdf2-hmac-sha256/spec"
            checked_lean(command, ["-DwarningAsError=true", "Pbkdf2Spec.lean"], directory, output)
        if selected == "chacha20":
            directory = ROOT / "src/crypto/cipher/chacha20/spec"
            for module in ("ChaCha20Counter", "ChaCha20QuarterRound"):
                checked_lean(command, ["-DwarningAsError=true", "-o", output / f"{module}.olean",
                                       f"{module}.lean"], directory, output)
            checked_lean(command, ["-DwarningAsError=true", "ChaCha20Stream.lean"], directory, output)
            checked_lean(command, ["-DwarningAsError=true", "ChaCha20WordOutput.lean"], directory, output)
        if selected == "poly1305":
            directory = ROOT / "src/crypto/mac/poly1305/spec"
            checked_lean(command, ["-DwarningAsError=true", "-o", output / "Poly1305Radix13.olean",
                                   "Poly1305Radix13.lean"], directory, output)
            checked_lean(command, ["-DwarningAsError=true", "Poly1305Window.lean"], directory, output)


if __name__ == "__main__":
    main()

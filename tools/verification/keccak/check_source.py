"""Replay the Rust Keccak permutation and absorb block through Charon and Lean."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from llbc import lean_module, require


ROOT = Path(__file__).resolve().parents[3]
ALGORITHM = ROOT / "src/crypto/hash/keccak-p1600"
CRATE = ALGORITHM / "impl/rust"
SPEC = ALGORITHM / "spec"
TOOLCHAIN = ROOT / "tools/verification/probe/toolchain-candidate.json"
LEAN_PIN = ROOT / "src/lean/lean-toolchain"
PROOF = "KeccakSourceRefinement.lean"
X64_TARGETS = {"x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"}
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
THEOREMS = {"sourceConstants_refine", "sourceRound_refines", "sourcePermutation_refines", "sourcePermutation_bits",
            "sourceAbsorbMix_refines", "sourceAbsorb_bits", "sourceAbsorb_blocks_bits", "sourceOutput_blocks_bits",
            "sourceSponge_blocks_bits"}
CONTROLS = (
    ("theta_rotation", ".rotate_left(1)", ".rotate_left(2)", "sourceRound_refines"),
    ("absorb_endianness", "u64::from_le_bytes", "u64::from_be_bytes", "sourceAbsorbMix_refines"),
    ("iota_constant", "0x0000_0000_0000_8082", "0x0000_0000_0000_8083", "sourceConstants_refine"),
)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def run(command, directory, env=None, success=True):
    result = subprocess.run(command, cwd=directory, env=env, capture_output=True, encoding="utf-8", errors="replace",
                            timeout=150)
    require((result.returncode == 0) == success,
            f"Unexpected result from {' '.join(map(str, command))}:\n{result.stdout}{result.stderr}")
    return result.stdout, result.stderr


def toolchain(charon, lean):
    pin = json.loads(TOOLCHAIN.read_bytes())
    charon = Path(charon).resolve(strict=True)
    charon_version = run([str(charon), "version"], ROOT)[0].strip()
    require(charon_version.endswith(f"({pin['charon']})"), f"Unexpected Charon revision {charon_version}")
    rust = run([str(charon), "toolchain-version"], ROOT)[0].strip()
    require(rust == pin["rust"], f"Unexpected Keccak Rust toolchain {rust}")
    compiler = run(["rustup", "run", rust, "rustc", "-Vv"], ROOT)[0].strip()
    host = re.search(r"^host: (\S+)$", compiler, re.M)
    require(host is not None and host[1] in X64_TARGETS, "Expected a supported Keccak x86-64 extraction host")
    lean_pin = LEAN_PIN.read_text(encoding="utf-8").strip()
    elan = shutil.which("elan")
    lean = [lean] if lean else ([elan, "run", lean_pin, "lean"] if elan else ["lean"])
    lean_version = run([*lean, "--version"], ROOT)[0].strip()
    require(f"version {lean_pin.split(':v')[1]}," in lean_version, f"Expected {lean_pin}, found {lean_version}")
    return charon, charon_version, rust, compiler, host[1], lean, lean_version


def audit(text):
    results = re.findall(
        r"^'Abc\.Refine\.Keccak\.Source\.(\w+)' "
        r"(?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)", text, flags=re.M,
    )
    return {name: [axiom.strip() for axiom in axioms.split(",")] if axioms else [] for name, axioms in results}


def verify(charon, lean, negative_controls):
    charon, version, rust, compiler, target, lean, lean_version = toolchain(charon, lean)
    src = CRATE / "src/lib.rs"
    inputs = [TOOLCHAIN, LEAN_PIN, src, CRATE / "Cargo.toml", ROOT / "tools/build/rust/Cargo.toml",
              ROOT / "tools/build/rust/Cargo.lock", SPEC / "KeccakRound.lean", SPEC / PROOF,
              Path(__file__).parent / "llbc.py", Path(__file__)]

    def hashes():
        return {path.resolve().relative_to(ROOT).as_posix(): digest(path) for path in inputs}

    before = hashes()
    original = src.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="abc-keccak-source-") as directory:
        work = Path(directory)

        def extract(label, mutant=None):
            path = work / f"{label}.llbc"
            ir_options = ["--preset=aeneas", "--start-from", "crate::absorb_rate_block", "--dest-file", str(path)]
            if mutant is None:
                args = ["cargo", *ir_options, "--", "--locked", "--offline", "--lib", "--no-default-features",
                        "--target", target]
            else:
                args = ["rustc", *ir_options, "--", str(mutant), "--crate-name", "abc_keccak_p1600", "--crate-type", "lib",
                        "--edition", "2021", "--target", target]
            env = {**os.environ, "RUSTUP_TOOLCHAIN": rust, "CARGO_NET_OFFLINE": "true",
                   "CARGO_TARGET_DIR": str(work / f"{label}-target")}
            _, log = run([str(charon), *args], CRATE if mutant is None else work, env)
            artifact = json.loads(path.read_bytes())
            require(artifact["charon_version"] == version.split()[0], "Unexpected Keccak LLBC release")
            return lean_module(artifact, target), {"sha256": digest(path),
                                                 "used_default_sysroot_fallback": "falling back to rustc" in log}

        def compile_lean(path, success=True):
            command = [*lean, f"--root={work}", "-DwarningAsError=true", "-o", str(path.with_suffix(".olean")), str(path)]
            return "".join(run(command, work, {**os.environ, "LEAN_PATH": str(work)}, success))

        first, first_ir = extract("first")
        second, second_ir = extract("second")
        require(first == second, "Fresh Keccak extractions changed generated Lean")
        for filename in ("KeccakRound.lean", PROOF):
            shutil.copyfile(SPEC / filename, work / filename)
        compile_lean(work / "KeccakRound.lean")
        generated = work / "KeccakLlbc.lean"
        generated.write_text(first, encoding="utf-8", newline="\n")
        generated_sha = digest(generated)
        compile_lean(generated)
        theorems = audit(compile_lean(work / PROOF))
        require(set(theorems) == THEOREMS and all(set(axioms) <= ALLOWED_AXIOMS for axioms in theorems.values()),
                f"Unexpected Keccak Lean audit {theorems}")

        controls = {}
        if negative_controls:
            mutant = work / "lib.rs"
            for label, old, new, expected in CONTROLS:
                require(original.count(old) == 1, f"Expected exactly one Keccak mutation site for {label}")
                mutant.write_text(original.replace(old, new, 1), encoding="utf-8", newline="\n")
                altered, altered_ir = extract(label, mutant)
                require(altered != first, f"Keccak control produced no changed Lean term for {label}")
                generated.write_text(altered, encoding="utf-8", newline="\n")
                compile_lean(generated)
                rejected = audit(compile_lean(work / PROOF, success=False))
                require("sorryAx" in rejected.get(expected, []), f"Keccak control failed outside {expected}")
                controls[label] = {"rust_sha256": digest(mutant), "llbc_sha256": altered_ir["sha256"],
                                   "lean_sha256": digest(generated), "rejected_theorem": expected}

    require(hashes() == before, "Keccak verification inputs changed during replay")
    return {"status": "keccak_llbc_permutation_and_absorb_checked", "target": target, "charon": version,
            "charon_executable_sha256": digest(charon), "rust": compiler, "lean": lean_version, "sources": before,
            "extractions": [first_ir, second_ir], "generated_lean_sha256": generated_sha,
            "audited_theorems": theorems, "negative_controls": controls}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--charon", default=os.environ.get("ABC_CHARON") or shutil.which("charon"))
    parser.add_argument("--lean", help="standalone Lean executable at the repository pin")
    parser.add_argument("--negative-controls", action="store_true")
    parser.add_argument("--output", type=Path, help="JSON receipt destination")
    args = parser.parse_args()
    if not args.charon:
        parser.exit(1, "Supply pinned Charon through --charon, ABC_CHARON or PATH\n")
    try:
        data = verify(args.charon, args.lean, args.negative_controls)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
    receipt = json.dumps(data, indent=2) + "\n"
    if args.output:
        args.output.write_text(receipt, encoding="utf-8", newline="\n")
    print(receipt, end="")


if __name__ == "__main__":
    main()

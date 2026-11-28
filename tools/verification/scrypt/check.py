"""Extract the active Rust BlockMix and Salsa20/8 and replay their RFC 7914 proofs."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from tools.verification.scrypt.blockmix_llbc import lean_body
from tools.verification.scrypt.salsa_llbc import SalsaCrate, lean_module, require


ROOT = Path(__file__).resolve().parents[3]
CRATE = ROOT / "src/crypto/kdf/scrypt/impl/rust"
SPEC = ROOT / "src/crypto/kdf/scrypt/spec"
TOOLCHAIN = ROOT / "tools/verification/probe/toolchain-candidate.json"
LEAN_PIN = ROOT / "src/lean/lean-toolchain"
PROOF = "ScryptSalsaSource.lean"
BLOCKMIX_PROOF = "ScryptBlockMixSource.lean"
SUPPORTED = {"x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"}
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
THEOREMS = {"sourceDoubleRound_refines", "sourceFeed_refines", "sourceSalsa8_refines", "sourceSalsaBytes_refines",
            "alternatingWithSourceSalsa_refines", "sourceBlockMixSeed_refines", "sourceBlockMixInput_refines",
            "sourceBlockMixSerialize_refines", "sourceBlockMixWordTrace_refines", "sourceBlockMixTraversal_refines",
            "sourceBlockMixBlocks_refines", "sourceBlockMixScatter_refines", "sourceBlockMixBytes_refines"}
CONTROLS = {
    "rotation": (".rotate_left(7)", ".rotate_left(6)", PROOF, "sourceDoubleRound_refines"),
    "round_count": ("let mut words = *state;\n    for _ in 0..4 {", "let mut words = *state;\n    for _ in 0..3 {",
                    PROOF, "sourceSalsa8_refines"),
    "blockmix_destination": ("let destination = index / 2 + (index % 2) * (blocks / 2);",
                             "let destination = index / 2 + (index % 2) * (blocks / 2) + 1;",
                             BLOCKMIX_PROOF, "sourceBlockMixTraversal_refines"),
    "blockmix_serialization": ("*bytes = word.to_le_bytes();", "*bytes = word.to_be_bytes();",
                               BLOCKMIX_PROOF, "sourceBlockMixSerialize_refines"),
}


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def run(command, work=ROOT, env=None, success=True):
    result = subprocess.run(command, cwd=work, env=env, capture_output=True, encoding="utf-8", errors="replace",
                            timeout=150)
    require((result.returncode == 0) == success,
            f"Unexpected result from {' '.join(map(str, command))}:\n{result.stdout}{result.stderr}")
    return result.stdout.strip(), result.stderr


def toolchain(charon, lean):
    pin = json.loads(TOOLCHAIN.read_bytes())
    charon = Path(charon).resolve(strict=True)
    version = run([str(charon), "version"])[0]
    require(version.endswith(f"({pin['charon']})"), f"Unexpected Charon version {version}")
    rust = run([str(charon), "toolchain-version"])[0]
    require(rust == pin["rust"], f"Unexpected Salsa20/8 Rust toolchain {rust}")
    compiler = run(["rustup", "run", rust, "rustc", "-Vv"])[0]
    host = re.search(r"^host: (\S+)$", compiler, re.M)
    require(host is not None and host[1] in SUPPORTED, "Expected a supported Salsa20/8 x86-64 extraction host")
    lean_pin = LEAN_PIN.read_text(encoding="utf-8").strip()
    elan = shutil.which("elan")
    lean = [lean] if lean else ([elan, "run", lean_pin, "lean"] if elan else ["lean"])
    lean_version = run([*lean, "--version"])[0]
    require(f"version {lean_pin.split(':v')[1]}," in lean_version, f"Expected {lean_pin}, got {lean_version}")
    return charon, version, rust, compiler, host[1], lean, lean_version


def audit(text):
    rows = re.findall(r"^'Abc\.Refine\.Scrypt\.Source\.(\w+)'\s+"
                      r"(?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)", text, flags=re.M)
    return {name: [item.strip() for item in axioms.split(",")] if axioms else [] for name, axioms in rows}


def verify(charon, lean, negative_controls):
    charon, version, rust, compiler, target, lean, lean_version = toolchain(charon, lean)
    models = ["ScryptBounds.lean", "ScryptFunctional.lean", "ScryptAlternating.lean", PROOF, BLOCKMIX_PROOF]
    src = CRATE / "src/lib.rs"
    inputs = [TOOLCHAIN, LEAN_PIN, src, CRATE / "Cargo.toml", ROOT / "tools/build/rust/Cargo.toml",
              ROOT / "tools/build/rust/Cargo.lock", ROOT / "tools/verification/keccak/llbc.py",
              Path(__file__), Path(__file__).with_name("salsa_llbc.py"), Path(__file__).with_name("blockmix_llbc.py"),
              *(SPEC / model for model in models)]

    def hashes():
        return {path.resolve().relative_to(ROOT).as_posix(): digest(path) for path in inputs}

    before = hashes()
    with tempfile.TemporaryDirectory(prefix="abc-scrypt-blockmix-") as scratch:
        work = Path(scratch)

        def extract(label, crate=CRATE):
            ir = work / f"{label}.llbc"
            env = {**os.environ, "RUSTUP_TOOLCHAIN": rust, "CARGO_NET_OFFLINE": "true",
                   "CARGO_TARGET_DIR": str(work / f"{label}-target")}
            locked = ["--locked"] if crate == CRATE else []
            _, stderr = run([str(charon), "cargo", "--preset=aeneas", "--start-from", "crate::block_mix", "--dest-file",
                             str(ir), "--", *locked, "--offline", "--lib", "--no-default-features", "--target", target],
                            crate, env)
            artifact = json.loads(ir.read_bytes())
            require(artifact["charon_version"] == version.split()[0], "Unexpected Salsa20/8 LLBC release")
            model = lean_module(artifact, target) + lean_body(SalsaCrate(artifact, target))
            return model, {"sha256": digest(ir), "used_default_sysroot_fallback": "falling back to rustc" in stderr}

        def compile_lean(path, success=True):
            command = [*lean, f"--root={work}", "-DwarningAsError=true", "-o", str(path.with_suffix(".olean")), str(path)]
            return "\n".join(run(command, work, {**os.environ, "LEAN_PATH": str(work)}, success))

        model, first = extract("first")
        repeat, second = extract("second")
        require(model == repeat, "Fresh scrypt extractions changed generated Lean")
        generated = work / "SalsaLlbc.lean"
        generated.write_text(model, encoding="utf-8", newline="\n")
        generated_hash = digest(generated)
        for filename in models:
            shutil.copyfile(SPEC / filename, work / filename)
        for path in (*(work / path for path in models[:-2]), generated):
            compile_lean(path)
        theorems = audit(compile_lean(work / PROOF)) | audit(compile_lean(work / BLOCKMIX_PROOF))
        require(set(theorems) == THEOREMS and all(set(axioms) <= ALLOWED_AXIOMS for axioms in theorems.values()),
                f"Unexpected scrypt Lean audit {theorems}")

        controls = {}
        if negative_controls:
            original = src.read_text(encoding="utf-8")
            pbkdf2 = ROOT / "src/crypto/kdf/pbkdf2-hmac-sha256/impl/rust"
            manifest = ('[package]\nname = "abc-scrypt"\nversion = "0.1.0"\nedition = "2021"\n'
                        f'[dependencies]\nabc-pbkdf2-hmac-sha256 = {{ path = {json.dumps(pbkdf2.as_posix())} }}\n')
            for label, (old, new, proof, theorem) in CONTROLS.items():
                require(original.count(old) == 1, f"Expected one scrypt mutation site for {label}")
                crate = work / label
                mutant = crate / "src/lib.rs"
                mutant.parent.mkdir(parents=True)
                mutant.write_text(original.replace(old, new, 1), encoding="utf-8", newline="\n")
                (crate / "Cargo.toml").write_text(manifest, encoding="utf-8", newline="\n")
                altered, ir = extract(label, crate)
                require(altered != model, f"scrypt mutation produced no change for {label}")
                generated.write_text(altered, encoding="utf-8", newline="\n")
                compile_lean(generated)
                if proof == BLOCKMIX_PROOF:
                    compile_lean(work / PROOF)
                rejected = audit(compile_lean(work / proof, success=False))
                require("sorryAx" in rejected.get(theorem, []),
                        "Changed source failed outside the targeted scrypt refinement")
                controls[label] = {"rust_sha256": digest(mutant), "llbc_sha256": ir["sha256"],
                                   "lean_sha256": digest(generated), "rejected_theorem": theorem}

    require(hashes() == before, "scrypt verification inputs changed during replay")
    return {"status": "scrypt_salsa8_and_blockmix_source_checked", "target": target, "charon": version,
            "charon_executable_sha256": digest(charon), "rust": compiler, "lean": lean_version, "sources": before,
            "extractions": [first, second], "generated_lean_sha256": generated_hash,
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

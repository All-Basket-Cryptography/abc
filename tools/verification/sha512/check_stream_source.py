"""Replay SHA-512's source-derived length and padding transitions."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import subprocess

import check
from check_source import CRATE, PIN, ROOT, SPEC, digest, run, toolchain
from stream_llbc import lean_stream_module, require


REFERENCE = ("Sha512Spec.lean", "Sha512Compression.lean", "Sha512Streaming.lean")
PROOF = "Sha512StreamSourceRefinement.lean"
THEOREMS = {
    "sourceRejects_refines", "sourceCount_refines", "acceptedCounterFits", "updateWithSourceGate_refines",
    "rejectedUpdate_preservesView", "sourceBitLengthFits", "emittedBlocks_refines",
    "emittedBlocks_byte_contract", "finalizeWithSourcePadding_refines",
}
CONTROLS = {
    "reject_exact_boundary": (
        "incoming > MAX_MESSAGE_BYTES", "incoming >= MAX_MESSAGE_BYTES", "sourceRejects_refines",
    ),
    "alter_marker": ("self.block[self.buffered] = 0x80", "self.block[self.buffered] = 0x81", "emittedBlocks_refines"),
}


def theorem_audit(text):
    found = re.findall(
        r"^'Abc\.Refine\.Sha512\.StreamSource\.(\w+)' "
        r"(?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)",
        text, flags=re.M,
    )
    return {name: [entry.strip() for entry in axioms.split(",")] if axioms else [] for name, axioms in found}


def verify(charon, lean, negative_controls):
    charon, version, rust, compiler, target = toolchain(charon)
    lean, lean_version = check.lean_command(lean)
    encoding = check.FOUNDATION / "Abc/Foundation/Encoding.lean"
    inputs = [PIN, check.PIN, check.RUST, CRATE / "Cargo.toml", ROOT / "tools/build/rust/Cargo.toml",
              ROOT / "tools/build/rust/Cargo.lock", encoding, *(SPEC / name for name in (*REFERENCE, PROOF)),
              *(Path(__file__).parent / name for name in
                ("check.py", "llbc.py", "check_source.py", "stream_llbc.py", "check_stream_source.py"))]

    def hashes():
        return {path.relative_to(ROOT).as_posix(): digest(path) for path in inputs}

    before = hashes()
    source = check.RUST.read_text(encoding="utf-8")
    check.checked_source(source)
    initial, constants = check.constants(source)
    flags = ["--preset=aeneas", "--start-from", "crate::digest"]
    cargo = ["--locked", "--offline", "--lib", "--no-default-features", "--target", target]

    with tempfile.TemporaryDirectory(prefix="abc-sha512-stream-") as directory:
        work = Path(directory)
        objects = work / "lean"
        objects.mkdir()

        def extract(label, mutant=None):
            ir = work / f"{label}.llbc"
            if mutant is None:
                args = ["cargo", *flags, "--dest-file", str(ir), "--", *cargo]
            else:
                args = ["rustc", *flags, "--dest-file", str(ir), "--", str(mutant), "--crate-name", "abc_sha512",
                        "--crate-type", "lib", "--edition", "2021", "--target", target]
            env = {**os.environ, "RUSTUP_TOOLCHAIN": rust, "CARGO_NET_OFFLINE": "true",
                   "CARGO_TARGET_DIR": str(work / f"{label}-target")}
            _, log = run([str(charon), *args], CRATE if mutant is None else work, env)
            artifact = json.loads(ir.read_bytes())
            require(artifact["charon_version"] == version.split()[0], "Unexpected digest LLBC release")
            return lean_stream_module(artifact, target), {
                "sha256": digest(ir), "used_default_sysroot_fallback": "falling back to rustc" in log,
            }

        def compile_(path, success=True):
            cmd = [*lean, f"--root={objects}", "-DwarningAsError=true", "-o", str(path.with_suffix(".olean")), str(path)]
            return "".join(run(cmd, objects, {**os.environ, "LEAN_PATH": str(objects)}, success))

        first, first_ir = extract("first")
        second, second_ir = extract("second")
        require(first == second, "Independent digest-closure extractions produced different Lean modules")
        encoded = objects / "Abc/Foundation/Encoding.lean"
        encoded.parent.mkdir(parents=True)
        shutil.copyfile(encoding, encoded)
        compile_(encoded)
        tables = ["namespace Abc.Refine.Sha512"]
        for name, words in (("rustInitial", initial), ("rustConstants", constants)):
            values = ", ".join(f"0x{word:016x}" for word in words)
            tables.append(f"def {name} : Array UInt64 := #[{values}]")
        tables.append("end Abc.Refine.Sha512")
        constants_module = objects / "Sha512RustConstants.lean"
        constants_module.write_text("\n".join(tables) + "\n", encoding="utf-8", newline="\n")
        compile_(constants_module)
        for name in REFERENCE:
            copied = objects / name
            shutil.copyfile(SPEC / name, copied)
            compile_(copied)
        generated = objects / "Sha512StreamLlbc.lean"
        generated.write_text(first, encoding="utf-8", newline="\n")
        compile_(generated)
        generated_hash = digest(generated)
        proof = objects / PROOF
        shutil.copyfile(SPEC / PROOF, proof)
        audit = theorem_audit(compile_(proof))
        require(set(audit) == THEOREMS and all(set(axioms) <= check.ALLOWED_AXIOMS for axioms in audit.values()),
                f"Unexpected SHA-512 stream theorem report {audit}")

        controls = {}
        if negative_controls:
            mutant = work / "lib.rs"
            for label, (old, new, theorem) in CONTROLS.items():
                require(source.count(old) == 1, f"Expected exactly one Rust mutation target for {label}")
                mutant.write_text(source.replace(old, new, 1), encoding="utf-8", newline="\n")
                changed, ir = extract(label, mutant)
                require(changed != first, f"Changed Rust path produced identical Lean source for {label}")
                generated.write_text(changed, encoding="utf-8", newline="\n")
                compile_(generated)
                rejected = theorem_audit(compile_(proof, success=False))
                require("sorryAx" in rejected.get(theorem, []), f"Lean rejected an unexpected control for {label}")
                controls[label] = {"rust_sha256": digest(mutant), "llbc_sha256": ir["sha256"],
                                   "lean_sha256": digest(generated), "rejected_theorem": theorem}

    require(hashes() == before, "SHA-512 source inputs changed during verification")
    return {"status": "sha512_llbc_stream_gate_and_padding_checked", "target": target,
            "charon": version, "charon_executable_sha256": digest(charon), "rust": compiler, "lean": lean_version,
            "sources": before, "extractions": [first_ir, second_ir], "generated_lean_sha256": generated_hash,
            "audited_theorems": audit, "negative_controls": controls}


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
        receipt = verify(args.charon, args.lean, args.negative_controls)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
    text = json.dumps(receipt, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8", newline="\n")
    print(text, end="")


if __name__ == "__main__":
    main()

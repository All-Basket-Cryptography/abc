"""Replay the Rust SHA3-256 digest and SHAKE256 finalizer source proofs."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from check_source import (ALLOWED_AXIOMS, CRATE, LEAN_PIN, ROOT, SPEC, TOOLCHAIN, digest, run, toolchain)
from llbc import lean_module, require
from reader_llbc import lean_reader_module
from wrapper_llbc import lean_wrapper_module


WRAPPERS = {"sha3-256": "digest", "shake256": "xof"}
WRAPPER_PROOF = "KeccakWrapperSourceRefinement.lean"
READER_PROOF = "KeccakReaderSourceRefinement.lean"
WRAPPER_THEOREMS = {"sourceSha3Padding_refines", "sourceShakePadding_refines", "sourceSha3Wire_refines",
            "sourceShakeWire_refines", "sourceSha3Digest_bits", "sourceShakeFinalize_bits"}
READER_THEOREMS = {"sourceReadRefresh_refines", "sourceReady_refines", "sourceReadCount_refines", "sourceReadRange_refines",
                   "sourceAfter_refines", "sourceSpan_refines", "sourceRead_refines", "sourceShakeRead_bits",
                   "sourceReadTrace_refines", "sourceShakeReadTrace_bits"}
CONTROLS = (
    ("sha3_domain", "sha3-256", "padded[tail.len()] = 0x06", "padded[tail.len()] = 0x07", "sourceSha3Padding_refines"),
    ("shake_domain", "shake256", "self.block[self.buffered] = 0x1f", "self.block[self.buffered] = 0x1e",
     "sourceShakePadding_refines"),
    ("shake_wire_endianness", "shake256", "lane.to_le_bytes()", "lane.to_be_bytes()", "sourceShakeWire_refines"),
    ("shake_refresh", "shake256", "if self.offset == RATE_BYTES {", "if self.offset != RATE_BYTES {",
     "sourceReadRefresh_refines"),
)


def audit(text):
    reports = re.findall(
        r"^'Abc\.Refine\.Keccak\.(?:WrapperSource|ReaderSource)\.(\w+)' "
        r"(?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)", text, flags=re.M,
    )
    return {name: [axiom.strip() for axiom in axioms.split(",")] if axioms else [] for name, axioms in reports}


def verify(charon, lean, negative_controls):
    charon, version, rust, compiler, target, lean, lean_version = toolchain(charon, lean)
    crates = {leaf: ROOT / "src/crypto/hash" / leaf / "impl/rust" for leaf in WRAPPERS}
    proofs = ("KeccakRound.lean", "KeccakSourceRefinement.lean", "KeccakReader.lean", "KeccakSpongeRead.lean",
              WRAPPER_PROOF, READER_PROOF)
    scripts = ("llbc.py", "check_source.py", "wrapper_llbc.py", "reader_llbc.py", "check_wrappers.py")
    inputs = [TOOLCHAIN, LEAN_PIN, ROOT / "tools/build/rust/Cargo.toml", ROOT / "tools/build/rust/Cargo.lock",
              *(crate / name for crate in (CRATE, *crates.values()) for name in ("Cargo.toml", "src/lib.rs")),
              *(SPEC / file for file in proofs), *(Path(__file__).parent / file for file in scripts)]

    def hashes():
        return {path.resolve().relative_to(ROOT).as_posix(): digest(path) for path in inputs}

    before = hashes()
    with tempfile.TemporaryDirectory(prefix="abc-keccak-wrapper-") as directory:
        work = Path(directory)

        def extract(label, crate, entry, dependency=False, locked=True):
            ir = work / f"{label}.llbc"
            options = ["--preset=aeneas", "--start-from", f"crate::{entry}", "--dest-file", str(ir)]
            if dependency:
                options += ["--include", "abc_keccak_p1600::RATE_BYTES"]
            cargo = (["--locked"] if locked else []) + ["--offline", "--lib", "--no-default-features", "--target", target]
            env = {**os.environ, "RUSTUP_TOOLCHAIN": rust, "CARGO_NET_OFFLINE": "true",
                   "CARGO_TARGET_DIR": str(work / f"{label}-target")}
            _, log = run([str(charon), "cargo", *options, "--", *cargo], crate, env)
            artifact = json.loads(ir.read_bytes())
            require(artifact["charon_version"] == version.split()[0], "Unexpected sponge wrapper LLBC release")
            return artifact, {"sha256": digest(ir), "used_default_sysroot_fallback": "falling back to rustc" in log}

        def compile_lean(path, success=True):
            command = [*lean, f"--root={work}", "-DwarningAsError=true", "-o", str(path.with_suffix(".olean")), str(path)]
            return "".join(run(command, work, {**os.environ, "LEAN_PATH": str(work)}, success))

        def extract_wrappers(suffix):
            return {leaf: extract(f"{leaf}-{suffix}", crates[leaf], entry, dependency=True)
                    for leaf, entry in WRAPPERS.items()}

        def combine(artifacts):
            return lean_wrapper_module(artifacts["sha3-256"][0], artifacts["shake256"][0], target)

        core, core_ir = extract("keccak", CRATE, "absorb_rate_block")
        first, second = extract_wrappers("first"), extract_wrappers("second")
        wrapper = combine(first)
        reader = lean_reader_module(first["shake256"][0], target)
        require(wrapper == combine(second) and reader == lean_reader_module(second["shake256"][0], target),
                "Fresh Rust sponge wrapper extractions changed generated Lean")
        for file in proofs:
            shutil.copyfile(SPEC / file, work / file)
        compile_lean(work / "KeccakRound.lean")
        core_file = work / "KeccakLlbc.lean"
        core_file.write_text(lean_module(core, target), encoding="utf-8", newline="\n")
        compile_lean(core_file)
        core_hash = digest(core_file)
        compile_lean(work / "KeccakSourceRefinement.lean")
        output = work / "KeccakWrapperLlbc.lean"
        output.write_text(wrapper, encoding="utf-8", newline="\n")
        wrapper_hash = digest(output)
        compile_lean(output)
        wrapper_audit = audit(compile_lean(work / WRAPPER_PROOF))
        compile_lean(work / "KeccakReader.lean")
        compile_lean(work / "KeccakSpongeRead.lean")
        reader_output = work / "KeccakReaderLlbc.lean"
        reader_output.write_text(reader, encoding="utf-8", newline="\n")
        reader_hash = digest(reader_output)
        compile_lean(reader_output)
        reader_audit = audit(compile_lean(work / READER_PROOF))
        positive = {**wrapper_audit, **reader_audit}
        require(set(wrapper_audit) == WRAPPER_THEOREMS and set(reader_audit) == READER_THEOREMS and
                all(set(axioms) <= ALLOWED_AXIOMS for axioms in positive.values()),
                f"Unexpected sponge wrapper theorem audit {positive}")

        controls = {}
        if negative_controls:
            for label, leaf, old, new, theorem in CONTROLS:
                source = (crates[leaf] / "src/lib.rs").read_text(encoding="utf-8")
                require(source.count(old) == 1, f"Expected exactly one sponge wrapper mutation site for {label}")
                isolated = work / label
                mutant = isolated / "src/lib.rs"
                mutant.parent.mkdir(parents=True)
                mutant.write_text(source.replace(old, new, 1), encoding="utf-8", newline="\n")
                local_keccak = json.dumps(CRATE.as_posix())
                manifest = (f'[package]\nname = "abc-{leaf}"\nversion = "0.1.0"\nedition = "2021"\n'
                            f'[dependencies]\nabc-keccak-p1600 = {{ path = {local_keccak} }}\n')
                (isolated / "Cargo.toml").write_text(manifest, encoding="utf-8", newline="\n")
                altered = {**first, leaf: extract(label, isolated, WRAPPERS[leaf], dependency=True, locked=False)}
                if theorem in READER_THEOREMS:
                    require(combine(altered) == wrapper, f"Reader mutation changed the wrapper for {label}")
                    output.write_text(wrapper, encoding="utf-8", newline="\n")
                    compile_lean(output)
                    compile_lean(work / WRAPPER_PROOF)
                    previous, generated, generated_path, proof = (
                        reader, lean_reader_module(altered[leaf][0], target), reader_output, READER_PROOF)
                else:
                    previous, generated, generated_path, proof = wrapper, combine(altered), output, WRAPPER_PROOF
                require(generated != previous, f"Sponge wrapper mutation produced no changed Lean for {label}")
                generated_path.write_text(generated, encoding="utf-8", newline="\n")
                compile_lean(generated_path)
                rejected = audit(compile_lean(work / proof, success=False))
                require("sorryAx" in rejected.get(theorem, []), f"Sponge wrapper mutation failed outside {theorem}")
                controls[label] = {"rust_sha256": digest(mutant), "llbc_sha256": altered[leaf][1]["sha256"],
                                   "lean_sha256": digest(generated_path), "rejected_theorem": theorem}

    require(hashes() == before, "Rust sponge wrapper inputs changed during replay")
    return {"status": "sha3_digest_and_shake_reader_source_checked", "target": target,
            "charon": version, "charon_executable_sha256": digest(charon), "rust": compiler, "lean": lean_version,
            "sources": before, "extractions": {"keccak": core_ir, **{leaf: [first[leaf][1], second[leaf][1]]
                                                                    for leaf in WRAPPERS}},
            "generated_lean_sha256": {"keccak": core_hash, "wrapper": wrapper_hash, "reader": reader_hash},
            "audited_theorems": positive, "negative_controls": controls}


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

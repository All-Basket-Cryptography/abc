"""Replay the Rust SHA-512 byte API using pinned Charon and Lean."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import check
from api_llbc import lean_api_module
from check_source import CRATE, PIN, ROOT, SPEC, digest, run, toolchain
from llbc import lean_module, require


REFERENCE = ("Sha512Spec", "Sha512Compression", "Sha512Streaming",
             "Sha512LlbcRefinement", "Sha512StreamSourceRefinement")
API_PROOF = "Sha512ApiSourceRefinement"
TRACE_PROOF = "Sha512TraceSourceRefinement"
THEOREMS = {"sourceCopied_refines", "sourceInitial_refines", "sourceEncode_refines",
            "sourceDriver_refines", "sourceDigest_refines", "sourceDigest_eq_composed", "sourceUpdate_refines",
            "sourceFinalize_refines", "sourceTrace_refines_accepted", "sourceTrace_refines_concat"}
CONTROLS = (
    ("wrong_copy_bound", "input.len().min(", "input.len().max(", "sourceCopied_refines"),
    ("wrong_digest_byte_order", "*chunk = word.to_be_bytes();", "*chunk = word.to_le_bytes();", "sourceEncode_refines"),
)
WRAPPER_CONTROL = ("Ok(state.finalize())", "Ok(Sha512::new().finalize())")


def theorem_audit(text):
    reports = re.findall(
        r"^'Abc\.Refine\.Sha512\.ApiSource\.(\w+)' "
        r"(?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)", text, flags=re.M,
    )
    return {name: [axiom.strip() for axiom in axioms.split(",")] if axioms else [] for name, axioms in reports}


def verify(charon, lean, negative_controls):
    charon, version, rust, compiler, target = toolchain(charon)
    lean, lean_version = check.lean_command(lean)
    encoding = check.FOUNDATION / "Abc/Foundation/Encoding.lean"
    inputs = [PIN, check.PIN, check.RUST, CRATE / "Cargo.toml", ROOT / "tools/build/rust/Cargo.toml",
              ROOT / "tools/build/rust/Cargo.lock", encoding,
              *(SPEC / f"{name}.lean" for name in (*REFERENCE, API_PROOF, TRACE_PROOF)),
              *(Path(__file__).parent / name for name in (
                  "check.py", "llbc.py", "check_source.py", "stream_llbc.py", "api_llbc.py", "check_api_source.py"))]

    def hashes():
        return {path.resolve().relative_to(ROOT).as_posix(): digest(path) for path in inputs}

    before = hashes()
    source = check.RUST.read_text(encoding="utf-8")
    check.checked_source(source)
    initial, constants = check.constants(source)
    cargo = ["--locked", "--offline", "--lib", "--no-default-features", "--target", target]

    with tempfile.TemporaryDirectory(prefix="abc-sha512-api-") as directory:
        work = Path(directory)
        objects = work / "lean"
        objects.mkdir()

        def extract(label, entry, mutant=None):
            ir = work / f"{label}.llbc"
            flags = ["--preset=aeneas", "--start-from", f"crate::{entry}", "--dest-file", str(ir)]
            if mutant is None:
                args = ["cargo", *flags, "--", *cargo]
            else:
                args = ["rustc", *flags, "--", str(mutant), "--crate-name", "abc_sha512", "--crate-type", "lib",
                        "--edition", "2021", "--target", target]
            env = {**os.environ, "RUSTUP_TOOLCHAIN": rust, "CARGO_NET_OFFLINE": "true",
                   "CARGO_TARGET_DIR": str(work / f"{label}-target")}
            _, log = run([str(charon), *args], CRATE if mutant is None else work, env)
            artifact = json.loads(ir.read_bytes())
            require(artifact["charon_version"] == version.split()[0], "Unexpected SHA-512 LLBC release")
            return artifact, {"sha256": digest(ir), "used_default_sysroot_fallback": "falling back to rustc" in log}

        def compile_file(path, succeeds=True):
            cmd = [*lean, f"--root={objects}", "-DwarningAsError=true", "-o", str(path.with_suffix(".olean")), str(path)]
            return "".join(run(cmd, objects, {**os.environ, "LEAN_PATH": str(objects)}, succeeds))

        def generate(name, terms):
            path = objects / f"{name}.lean"
            path.write_text(terms, encoding="utf-8", newline="\n")
            compile_file(path)
            return digest(path)

        def copy_compile(name):
            path = objects / f"{name}.lean"
            shutil.copyfile(SPEC / path.name, path)
            return compile_file(path)

        first, first_ir = extract("first", "digest")
        second, second_ir = extract("second", "digest")
        compression, compression_ir = extract("compression", "compress")
        stream, api = lean_api_module(first, target)
        require((stream, api) == lean_api_module(second, target), "Fresh SHA-512 API extractions changed generated Lean")

        encoded = objects / "Abc/Foundation/Encoding.lean"
        encoded.parent.mkdir(parents=True)
        shutil.copyfile(encoding, encoded)
        compile_file(encoded)
        tables = ["namespace Abc.Refine.Sha512"]
        for name, words in (("rustInitial", initial), ("rustConstants", constants)):
            values = ", ".join(f"0x{word:016x}" for word in words)
            tables.append(f"def {name} : Array UInt64 := #[{values}]")
        tables.append("end Abc.Refine.Sha512")
        generate("Sha512RustConstants", "\n".join(tables) + "\n")
        for name in REFERENCE[:3]:
            copy_compile(name)
        compression_hash = generate("Sha512Llbc", lean_module(compression, target))
        copy_compile("Sha512LlbcRefinement")
        stream_hash = generate("Sha512StreamLlbc", stream)
        copy_compile("Sha512StreamSourceRefinement")
        api_hash = generate("Sha512ApiLlbc", api)
        audit = theorem_audit(copy_compile(API_PROOF) + copy_compile(TRACE_PROOF))
        require(set(audit) == THEOREMS and all(set(axioms) <= check.ALLOWED_AXIOMS for axioms in audit.values()),
                f"Unexpected SHA-512 API theorem audit {audit}")

        controls = {}
        if negative_controls:
            mutant = work / "lib.rs"
            for label, old, new, theorem in CONTROLS:
                require(source.count(old) == 1, f"Expected exactly one SHA-512 mutation site for {label}")
                mutant.write_text(source.replace(old, new, 1), encoding="utf-8", newline="\n")
                artifact, ir = extract(label, "digest", mutant)
                mutant_stream, changed = lean_api_module(artifact, target)
                require(mutant_stream == stream and changed != api, f"Unexpected changed Lean module for {label}")
                changed_hash = generate("Sha512ApiLlbc", changed)
                rejected = theorem_audit(compile_file(objects / f"{API_PROOF}.lean", succeeds=False))
                require("sorryAx" in rejected.get(theorem, []), f"Unrelated Lean failure for {label}")
                controls[label] = {"rust_sha256": digest(mutant), "llbc_sha256": ir["sha256"],
                                   "lean_sha256": changed_hash, "rejected_theorem": theorem}

            old, new = WRAPPER_CONTROL
            require(source.count(old) == 1, "Expected the SHA-512 wrapper mutation site")
            mutant.write_text(source.replace(old, new, 1), encoding="utf-8", newline="\n")
            artifact, ir = extract("wrong_wrapper_context", "digest", mutant)
            reason = "The SHA-512 wrapper must return the finalized updated context"
            try:
                lean_api_module(artifact, target)
            except ValueError as error:
                require(str(error) == reason, f"Unexpected SHA-512 wrapper rejection: {error}")
            else:
                raise ValueError("The SHA-512 wrapper accepted a fresh context after updating a different one")
            controls["wrong_wrapper_context"] = {"rust_sha256": digest(mutant), "llbc_sha256": ir["sha256"],
                                                  "rejected_by_lowering": reason}

    require(hashes() == before, "SHA-512 API source inputs changed during verification")
    return {"status": "sha512_llbc_byte_api_checked", "target": target, "charon": version,
            "charon_executable_sha256": digest(charon), "rust": compiler, "lean": lean_version,
            "sources": before, "extractions": {"digest": [first_ir, second_ir], "compress": compression_ir},
            "generated_lean_sha256": {"api": api_hash, "stream": stream_hash, "compression": compression_hash},
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

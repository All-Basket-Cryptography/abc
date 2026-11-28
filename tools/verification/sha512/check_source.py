"""Extract SHA-512 compression with Charon and check its generated Lean terms."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import check
from llbc import lean_module, require


SPEC = check.SPEC
ROOT = check.ROOT
CRATE = check.ALGORITHM / "impl/rust"
PIN = ROOT / "tools/verification/probe/toolchain-candidate.json"
SCOPE = ["Sha512Spec.lean", "Sha512Compression.lean", "Sha512LlbcRefinement.lean"]
TARGETS = {"x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"}
THEOREMS = {"generatedLoad_refines", "generatedSchedule_refines", "generatedRound_refines",
            "generatedFeed_refines", "generatedCompression_eq", "generatedCompression_refines"}


def run(command, cwd, env=None, expect_success=True):
    result = subprocess.run(command, cwd=cwd, env=env, encoding="utf-8", errors="replace",
                            capture_output=True, timeout=150)
    if (result.returncode == 0) != expect_success:
        raise ValueError(f"Unexpected result from {' '.join(map(str, command))}:\n"
                         f"{result.stdout}{result.stderr}")
    return result.stdout, result.stderr


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def toolchain(charon):
    pin = json.loads(PIN.read_bytes())
    path = Path(charon).resolve(strict=True)
    version = run([str(path), "version"], ROOT)[0].strip()
    require(version.endswith(f"({pin['charon']})"), f"Unexpected Charon revision {version}")
    rust = run([str(path), "toolchain-version"], ROOT)[0].strip()
    require(rust == pin["rust"], f"Unexpected extraction Rust version {rust}")
    compiler = run(["rustup", "run", rust, "rustc", "-Vv"], ROOT)[0].strip()
    host = re.search(r"^host: (\S+)$", compiler, re.M)
    require(host is not None and host[1] in TARGETS, "Expected a supported x86-64 Rust extraction host")
    return path, version, rust, compiler, host[1]


def verify(charon, lean, negative_controls):
    charon, version, rust, compiler, target = toolchain(charon)
    lean, lean_version = check.lean_command(lean)
    inputs = [PIN, check.PIN, check.RUST, CRATE / "Cargo.toml",
              ROOT / "tools/build/rust/Cargo.toml", ROOT / "tools/build/rust/Cargo.lock",
              check.FOUNDATION / "Abc/Foundation/Encoding.lean",
              *(SPEC / file for file in SCOPE), *(Path(__file__).parent / file
                                                for file in ("check.py", "llbc.py", "check_source.py"))]

    def hashes():
        return {path.relative_to(ROOT).as_posix(): digest(path) for path in inputs}

    before = hashes()
    source = check.RUST.read_text(encoding="utf-8")
    check.checked_source(source)
    initial, constants = check.constants(source)
    extraction = ["--preset=aeneas", "--start-from", "crate::compress"]
    cargo = ["--locked", "--offline", "--lib", "--no-default-features", "--target", target]

    with tempfile.TemporaryDirectory(prefix="abc-sha512-llbc-") as temporary:
        work = Path(temporary)
        objects = work / "objects"
        objects.mkdir()

        def extract(label, scratch_source=None):
            llbc = work / f"{label}.llbc"
            args = ["cargo", *extraction, "--dest-file", str(llbc), "--", *cargo]
            if scratch_source is not None:
                args = ["rustc", *extraction, "--dest-file", str(llbc), "--", str(scratch_source),
                        "--crate-name", "abc_sha512", "--crate-type", "lib", "--edition", "2021",
                        "--target", target]
            env = {**os.environ, "RUSTUP_TOOLCHAIN": rust, "CARGO_NET_OFFLINE": "true",
                   "CARGO_TARGET_DIR": str(work / f"{label}-target")}
            _, log = run([str(charon), *args], CRATE if scratch_source is None else work, env)
            artifact = json.loads(llbc.read_bytes())
            require(artifact["charon_version"] == version.split()[0], "Unexpected Charon artifact version")
            return lean_module(artifact, target), {
                "sha256": digest(llbc), "used_default_sysroot_fallback": "falling back to rustc" in log,
            }

        def compile_lean(path, expect_success=True):
            out, err = run(
                [*lean, f"--root={objects}", "-DwarningAsError=true", "-o",
                 str(path.with_suffix(".olean")), str(path)],
                objects, {**os.environ, "LEAN_PATH": str(objects)}, expect_success,
            )
            return out + err

        first, first_receipt = extract("first")
        second, second_receipt = extract("second")
        require(first == second, "Independent Charon derivative modules differ")

        encoding = objects / "Abc/Foundation/Encoding.lean"
        encoding.parent.mkdir(parents=True)
        shutil.copyfile(check.FOUNDATION / "Abc/Foundation/Encoding.lean", encoding)
        compile_lean(encoding)
        tables = ["namespace Abc.Refine.Sha512"]
        for name, words in (("rustInitial", initial), ("rustConstants", constants)):
            entries = ", ".join(f"0x{word:016x}" for word in words)
            tables.append(f"def {name} : Array UInt64 := #[{entries}]")
        tables.append("end Abc.Refine.Sha512")
        generated_tables = objects / "Sha512RustConstants.lean"
        generated_tables.write_text("\n".join(tables) + "\n", encoding="utf-8", newline="\n")
        compile_lean(generated_tables)
        for name in SCOPE[:2]:
            copy = objects / name
            shutil.copyfile(SPEC / name, copy)
            compile_lean(copy)
        generated = objects / "Sha512Llbc.lean"
        generated.write_text(first, encoding="utf-8", newline="\n")
        compile_lean(generated)
        derivative = digest(generated)
        proof = objects / SCOPE[-1]
        shutil.copyfile(SPEC / SCOPE[-1], proof)
        audit = compile_lean(proof)
        reports = re.findall(
            r"^'Abc\.Refine\.Sha512\.Llbc\.(\w+)' (?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)",
            audit, flags=re.M,
        )
        theorems = {name: [axiom.strip() for axiom in axioms.split(",")] if axioms else []
                    for name, axioms in reports}
        require(len(reports) == len(THEOREMS) and set(theorems) == THEOREMS and
                all(set(items) <= check.ALLOWED_AXIOMS for items in theorems.values()),
                f"Unexpected Charon integration proof audit:\n{audit}")

        controls = {}
        if negative_controls:
            mutant = work / "lib.rs"
            changed = source.replace("e.rotate_right(14)", "e.rotate_right(15)", 1)
            require(changed != source, "Missing the selected Rust rotation")
            mutant.write_text(changed, encoding="utf-8", newline="\n")
            altered, altered_receipt = extract("rotation", mutant)
            require(altered != first, "Changing the Rust rotation did not change the generated Lean terms")
            generated.write_text(altered, encoding="utf-8", newline="\n")
            compile_lean(generated)
            rejection = compile_lean(proof, expect_success=False)
            require("Tactic `rfl` failed" in rejection and "Spec.Sha512.round" in rejection,
                    f"The changed Rust rotation failed outside the round-equivalence proof:\n{rejection}")
            controls["changed_rust_rotation_rejected_by_lean"] = {
                "source_sha256": digest(mutant), "llbc_sha256": altered_receipt["sha256"],
                "generated_lean_sha256": digest(generated),
            }

    require(hashes() == before, "Extraction or proof inputs changed during replay")
    return {"status": "sha512_llbc_compression_body_model_checked", "target": target,
            "charon": version, "charon_executable_sha256": digest(charon),
            "rust": compiler, "lean": lean_version, "sources": before,
            "generated_lean_sha256": derivative, "extractions": [first_receipt, second_receipt],
            "audited_theorems": theorems, "negative_controls": controls}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--charon", default=os.environ.get("ABC_CHARON") or shutil.which("charon"),
                        help="path to pinned Charon executable")
    parser.add_argument("--lean", help="use this Lean executable with the repository pin")
    parser.add_argument("--negative-controls", action="store_true", help="compile and reject an altered Rust rotation")
    parser.add_argument("--output", type=Path, help="save the verification receipt to this JSON file")
    args = parser.parse_args()
    if not args.charon:
        parser.exit(1, "Supply pinned Charon using --charon, ABC_CHARON or PATH\n")
    try:
        report = verify(args.charon, args.lean, args.negative_controls)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
    envelope = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(envelope, encoding="utf-8", newline="\n")
    print(envelope, end="")


if __name__ == "__main__":
    main()

"""Replay the pinned Rust AES-256 byte-field source refinement."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import mkdtemp

from translate import ByteOperations, require, statements, translate


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AES = ROOT / "src/crypto/cipher/aes256"
CRATE = AES / "impl/rust"
PROOF = HERE / "Aes256SourceRefinement.lean"
PIN = ROOT / "tools/verification/probe/toolchain-candidate.json"
INPUTS = [PIN, PROOF, HERE / "translate.py", Path(__file__).resolve(), CRATE / "Cargo.toml", CRATE / "src/lib.rs",
          ROOT / "tools/build/rust/Cargo.toml", ROOT / "tools/build/rust/Cargo.lock"]
THEOREMS = {f"Abc.Refine.Aes256.{name}" for name in
            ("source_mul_x_refines_fips", "source_square_refines_field", "source_field_examples",
             "source_mix_column_refines_fips", "source_mix_column_example")}
AXIOM = re.compile(r"^'([^']+)' (?:depends on axioms:\s*\[([^\]]*)\]|does not depend on any axioms)$", re.M)
ALLOWED = {"propext", "Classical.choice", "Quot.sound"}


def digest(candidate):
    return sha256(candidate.read_bytes()).hexdigest()


def inputs():
    return {file.relative_to(ROOT).as_posix(): digest(file) for file in INPUTS}


def locate(term, expected):
    if term == expected:
        yield term
    elif isinstance(term, list):
        for child in term:
            yield from locate(child, expected)
    elif isinstance(term, dict):
        for child in term.values():
            yield from locate(child, expected)


def check(options, run):
    pins = json.loads(PIN.read_bytes())
    source = inputs()
    env = {**os.environ, "RUSTUP_TOOLCHAIN": pins["rust"], "CARGO_NET_OFFLINE": "true"}

    def execute(name, command, *, cwd=ROOT, overrides=None, checked=True):
        command = list(map(str, command))
        result = subprocess.run(command, cwd=cwd, env={**env, **(overrides or {})}, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=180)
        log = run / f"{name}.log"
        log.write_text(json.dumps(command) + "\n" + result.stdout + result.stderr, encoding="utf-8")
        require(not checked or result.returncode == 0, f"{name} failed. See {log}")
        return result

    charon = execute("charon-version", [options.charon, "version"]).stdout.strip()
    require(pins["charon"] in charon and execute("rust-pin", [options.charon, "toolchain-version"]).stdout.strip()
            == pins["rust"], "Wrong Charon revision or Rust pin")
    rust = execute("rust-version", ["rustc", "-Vv"]).stdout.strip()
    target = next(line.removeprefix("host: ") for line in rust.splitlines() if line.startswith("host: "))
    lean = execute("lean-version", [options.lean, "--version"]).stdout.strip()
    require(f"version {pins['lean'].split(':v')[-1]}," in lean, "Wrong Lean version")
    selection = ["--preset=aeneas", "--consts", "values", "--start-from", "crate"]
    build = ["--locked", "--offline", "--no-default-features", "--lib", "--target", target]

    def emit_model(directory, llbc):
        model = directory / "Aes256Llbc.lean"
        model.write_text(translate(llbc), encoding="utf-8", newline="\n")
        return model

    def extract(label):
        directory = run / label
        directory.mkdir()
        raw = directory / "aes256.llbc"
        execute(f"{label}-extract", [options.charon, "cargo", *selection, "--dest-file", raw, "--", *build],
                cwd=CRATE, overrides={"CARGO_TARGET_DIR": str(directory / "target")})
        llbc = json.loads(raw.read_bytes())
        model = emit_model(directory, llbc)
        return llbc, model, {"llbc_sha256": digest(raw), "lean_model_sha256": digest(model)}

    llbc, model, first = extract("first")
    _, _, second = extract("second")
    require(first["lean_model_sha256"] == second["lean_model_sha256"], "Non-reproducible Lean model")
    objects = run / "objects"
    objects.mkdir()

    def compile_module(name, source_, output, lookup, *, checked=True):
        return execute(name, [options.lean, f"--root={source_.parent}", "-DwarningAsError=true", "-o",
                              output / (source_.stem + ".olean"), source_],
                       overrides={"LEAN_PATH": os.pathsep.join(map(str, lookup))}, checked=checked)

    compile_module("compile-source", model, objects, [objects])
    rows = AXIOM.findall(compile_module("compile-proof", PROOF, objects, [objects]).stdout)
    require(len(rows) == len(THEOREMS) and {name for name, _ in rows} == THEOREMS, "Unexpected AES axiom coverage")
    axioms = {name: [part.strip() for part in values.split(",") if part.strip()] for name, values in rows}
    require(all(set(values) <= ALLOWED for values in axioms.values()), "Unapproved AES proof axiom")

    negative = {}
    def reject(label, theorem):
        directory = run / label
        directory.mkdir()
        changed = emit_model(directory, llbc)
        require(digest(changed) != first["lean_model_sha256"], f"{label} mutant did not change the model")
        compile_module(f"compile-{label}", changed, directory, [directory, objects])
        rejected = compile_module(f"reject-{label}", PROOF, directory, [directory, objects], checked=False)
        reported = dict(AXIOM.findall(rejected.stdout))
        require(rejected.returncode != 0 and "Tactic `decide` proved that the proposition" in rejected.stdout
                and "sorryAx" in reported.get(f"Abc.Refine.Aes256.{theorem}", ""),
                f"Lean did not reject the changed {label} example")
        negative[label] = {"status": "rejected", "model_sha256": digest(changed), "log": f"reject-{label}.log"}

    if options.check_mutants:
        for label, kind, original, modified in [("reduction", "U8", "27", "26"), ("spread", "U16", "21845", "21844")]:
            (constant,) = locate(llbc, [kind, original])
            constant[1] = modified
            reject(label, "source_field_examples")
            constant[1] = original
        mix = ByteOperations(llbc).local("mix_column")["body"]["Structured"]["body"]
        (column,) = [update["Aggregate"][1] for tag, (destination, update) in
                     (item for item in statements(mix) if item[0] == "Assign")
                     if "Projection" in destination["kind"] and "Array" in update["Aggregate"][0]]
        column[0], column[1] = column[1], column[0]
        reject("column-order", "source_mix_column_example")
    require(inputs() == source, "Source inputs changed during replay")
    return {"status": "source_llbc_refinement_checked", "target": target, "rust": rust, "charon": charon, "lean": lean,
            "selection": selection, "cargo": build, "source_digests": source, "first": first, "second": second,
            "theorems": axioms, "negative_checks": negative}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--charon", default=os.environ.get("ABC_CHARON", "charon"))
    parser.add_argument("--lean", default=os.environ.get("ABC_LEAN", "lean"))
    parser.add_argument("--output", type=Path, default=ROOT / ".abc/aes256-extraction")
    parser.add_argument("--check-mutants", action="store_true")
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    run = Path(mkdtemp(prefix="run-", dir=options.output.resolve()))
    result = check(options, run)
    (run / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({**result, "path": str(run)}, indent=2))


if __name__ == "__main__":
    main()

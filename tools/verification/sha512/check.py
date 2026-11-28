"""Check the SHA-512 functional model against the reviewed portable Rust source."""

import argparse
from hashlib import sha256
import json
from math import isqrt
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]
FOUNDATION = ROOT / "src/lean"
ALGORITHM = ROOT / "src/crypto/hash/sha512"
SPEC = ALGORITHM / "spec"
RUST = ALGORITHM / "impl/rust/src/lib.rs"
PIN = FOUNDATION / "lean-toolchain"
COMPRESS_BODY_SHA256 = "cfa3bc06e545ceb32ba2fc20268e7839cbb27256b37da29f01a58dee320623c2"
PRODUCTION_SOURCE_SHA256 = "5788f93a602cc0736d92c88f80d1fb5f5cb634ec5ae75e7d0c387d83cceb4724"
THEOREMS = {"loadWord_refines", "schedule_refines", "rounds_refine",
            "constantTable_refines", "compress_refines", "source_block_contract",
            "source_digest_contract", "source_trace_contract",
            "Streaming.checkedLength_matches_domain", "Streaming.finalBlocks_bytes",
            "Streaming.update_rejects_without_mutation", "Streaming.foldCompress_refines",
            "Streaming.digestView_refines", "Streaming.finalizeTrace_refines_accepted",
            "Streaming.finalizeTrace_refines_concat"}
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}

CONTRACT = """import Sha512Streaming

namespace Abc.Refine.Sha512

theorem source_block_contract (initial : Registers) (block : List Abc.Spec.Sha512.Byte)
    (width : block.length = 128) :
    toSpecState (compress initial block) = Abc.Spec.Sha512.compress (toSpecState initial) block :=
  compress_refines initial block width

theorem source_digest_contract (message : List Abc.Spec.Sha512.Byte) :
    Streaming.digestView message = Abc.Spec.Sha512.digest message :=
  Streaming.digestView_refines message

theorem source_trace_contract (chunks : List (List Abc.Spec.Sha512.Byte))
    (domain : 8 * chunks.flatten.length < 2 ^ 128) :
    some (Streaming.finalizeTrace chunks) = Abc.Spec.Sha512.digest chunks.flatten :=
  Streaming.finalizeTrace_refines_concat chunks domain

#print axioms source_block_contract
#print axioms source_digest_contract
#print axioms source_trace_contract

end Abc.Refine.Sha512
"""


def checked_source(source):
    if len(re.findall(r"(?m)^const BLOCK_BYTES: usize = 128;$", source)) != 1:
        raise ValueError("The Rust block size declaration changed")
    matches = re.findall(r"(?ms)^fn compress\([^\n]*\) \{\n.*?^\}", source)
    if len(matches) != 1 or sha256(matches[0].encode()).hexdigest() != COMPRESS_BODY_SHA256:
        raise ValueError("The Rust compression body changed and requires model review")
    production, separator, _ = source.partition("\n#[cfg(test)]\n")
    if not separator or sha256(production.encode()).hexdigest() != PRODUCTION_SOURCE_SHA256:
        raise ValueError("The Rust production source changed and requires model review")


def literal_words(source, name, width):
    matches = re.findall(rf"(?ms)^const {name}: \[u64; {width}\] = \[([^\]]*)\];$", source)
    if len(matches) != 1 or not re.fullmatch(r"(?:\s*0x[0-9a-f]{16}\s*,){%d}\s*" % width, matches[0]):
        raise ValueError(f"Unexpected Rust table declaration for {name}")
    return [int(word.strip(), 16) for word in matches[0].strip().rstrip(",").split(",")]


def first_primes(count):
    primes = []
    number = 2
    while len(primes) < count:
        if all(number % divisor for divisor in primes if divisor * divisor <= number):
            primes.append(number)
        number += 1
    return primes


def cube_root_floor(number):
    lower, upper = 0, 1 << ((number.bit_length() + 2) // 3)
    while upper - lower > 1:
        midpoint = (lower + upper) // 2
        if midpoint ** 3 <= number:
            lower = midpoint
        else:
            upper = midpoint
    return lower


def constants(source):
    initial = literal_words(source, "INITIAL_STATE", 8)
    rounds = literal_words(source, "ROUND_CONSTANTS", 80)
    primes = first_primes(80)
    mask = (1 << 64) - 1
    if initial != [isqrt(p << 128) & mask for p in primes[:8]]:
        raise ValueError("Rust initialization words differ from the FIPS square roots")
    if rounds != [cube_root_floor(p << 192) & mask for p in primes]:
        raise ValueError("Rust round words differ from the FIPS cube roots")
    return initial, rounds


def lean_command(explicit):
    pin = PIN.read_text(encoding="utf-8").strip()
    elan = shutil.which("elan")
    command = [explicit] if explicit else ([elan, "run", pin, "lean"] if elan else ["lean"])
    version = subprocess.check_output([*command, "--version"], encoding="utf-8", timeout=20).strip()
    if f"version {pin.split(':v')[1]}," not in version:
        raise ValueError(f"Expected {pin}, found {version}")
    return command, version


def check_negative(work, compile_lean, source):
    mutated = source.replace("rotate_right(14)", "rotate_right(15)", 1)
    try:
        checked_source(mutated)
    except ValueError as error:
        if "compression body changed" not in str(error):
            raise
    else:
        raise ValueError("The altered Rust rotation passed the source guard")
    bad_table = source.replace("0x428a2f98d728ae22", "0x428a2f98d728ae23", 1)
    try:
        constants(bad_table)
    except ValueError as error:
        if "FIPS cube roots" not in str(error):
            raise
    else:
        raise ValueError("An altered Rust round constant passed the mathematical table check")
    model = (SPEC / "Sha512Compression.lean").read_text(encoding="utf-8")
    mutant = work / "Sha512CompressionMutant.lean"
    mutant.write_text(model.replace("rotate r.e 14", "rotate r.e 15", 1), encoding="utf-8")
    result = compile_lean(mutant, work / "Sha512CompressionMutant.olean", expect_success=False)
    if "rfl" not in result or "Spec.Sha512.round" not in result:
        raise ValueError(f"The altered model failed outside the round equality check:\n{result}")
    bad_padding = source.replace("self.block[self.buffered] = 0x80", "self.block[self.buffered] = 0x81", 1)
    try:
        checked_source(bad_padding)
    except ValueError as error:
        if "production source changed" not in str(error):
            raise
    else:
        raise ValueError("The altered Rust padding passed the source guard")
    padding_model = (SPEC / "Sha512Streaming.lean").read_text(encoding="utf-8")
    padding_mutant = work / "Sha512StreamingMutant.lean"
    padding_mutant.write_text(padding_model.replace("pending ++ [0x80]", "pending ++ [0x81]", 1), encoding="utf-8")
    result = compile_lean(padding_mutant, work / "Sha512StreamingMutant.olean", expect_success=False)
    if "change" not in result or "finalBlocks_bytes" not in result:
        raise ValueError(f"The altered model failed outside the padding equality check:\n{result}")
    return ["rust_rotation_rejected", "rust_constant_rejected", "lean_round_equality_rejected",
            "rust_padding_rejected", "lean_padding_equality_rejected"]


def verify(command, version, negative):
    files = [RUST, PIN, FOUNDATION / "Abc/Foundation/Encoding.lean",
             SPEC / "Sha512Spec.lean", SPEC / "Sha512Compression.lean", SPEC / "Sha512Streaming.lean",
             Path(__file__).resolve()]

    def hashes():
        return {path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()).hexdigest() for path in files}

    before = hashes()
    source = RUST.read_text(encoding="utf-8")
    checked_source(source)
    initial_words, round_words = constants(source)
    with tempfile.TemporaryDirectory(prefix="abc-sha512-formal-") as directory:
        work = Path(directory)

        def compile_lean(path, output, expect_success=True):
            result = subprocess.run(
                [*command, f"--root={work}", "-DwarningAsError=true", "-o", str(output), str(path)],
                cwd=work, env={**os.environ, "LEAN_PATH": str(work)}, encoding="utf-8",
                capture_output=True, timeout=90,
            )
            log = result.stdout + result.stderr
            if (result.returncode == 0) != expect_success:
                raise ValueError(f"Unexpected Lean result for {path.name}:\n{log}")
            return log

        encoding = work / "Abc/Foundation/Encoding.lean"
        encoding.parent.mkdir(parents=True)
        shutil.copyfile(FOUNDATION / "Abc/Foundation/Encoding.lean", encoding)
        compile_lean(encoding, encoding.with_suffix(".olean"))
        generated = work / "Sha512RustConstants.lean"
        tables = ["namespace Abc.Refine.Sha512"]
        for name, words in (("rustInitial", initial_words), ("rustConstants", round_words)):
            entries = ", ".join(f"0x{word:016x}" for word in words)
            tables.append(f"def {name} : Array UInt64 := #[{entries}]")
        tables.append("end Abc.Refine.Sha512")
        generated.write_text(
            "\n".join(tables) + "\n", encoding="utf-8", newline="\n",
        )
        compile_lean(generated, generated.with_suffix(".olean"))
        audit = ""
        for file in ("Sha512Spec.lean", "Sha512Compression.lean", "Sha512Streaming.lean"):
            destination = work / file
            shutil.copyfile(SPEC / file, destination)
            audit += compile_lean(destination, destination.with_suffix(".olean"))
        contract = work / "Sha512Contract.lean"
        contract.write_text(CONTRACT, encoding="utf-8", newline="\n")
        audit += compile_lean(contract, contract.with_suffix(".olean"))
        controls = check_negative(work, compile_lean, source) if negative else []
        generated_hash = sha256(generated.read_bytes()).hexdigest()

    reports = re.findall(
        r"^'Abc\.Refine\.Sha512\.((?:Streaming\.)?\w+)' (?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)",
        audit, flags=re.M,
    )
    theorems = {name: [axiom.strip() for axiom in axioms.split(",")] if axioms else []
                for name, axioms in reports}
    if (len(reports) != len(THEOREMS) or set(theorems) != THEOREMS or
            any(set(axioms) - ALLOWED_AXIOMS for axioms in theorems.values())):
        raise ValueError(f"Unexpected theorem or axiom report:\n{audit}")
    if hashes() != before:
        raise ValueError("Proof inputs changed during verification")
    return {"status": "sha512_functional_model_checked", "lean": version, "sources": before,
            "rust_compression_body_sha256": COMPRESS_BODY_SHA256,
            "rust_production_source_sha256": PRODUCTION_SOURCE_SHA256,
            "generated_constants_sha256": generated_hash, "theorems": theorems, "negative_controls": controls}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", help="use this Lean executable with the repository pin")
    parser.add_argument("--negative-controls", action="store_true", help="confirm that altered inputs fail")
    parser.add_argument("--output", type=Path, help="save the verification receipt to this JSON file")
    args = parser.parse_args()
    try:
        command, version = lean_command(args.lean)
        report = verify(command, version, args.negative_controls)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
    envelope = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(envelope, encoding="utf-8", newline="\n")
    print(envelope, end="")


if __name__ == "__main__":
    main()

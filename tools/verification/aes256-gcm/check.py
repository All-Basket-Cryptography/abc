"""Replay the portable Rust GHASH and authentication gate refinements."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import mkdtemp

from translate import ScalarLoop, ident, local_operand, meaningful, name_segments, require, translate


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCOPE = ROOT / "src/crypto/aead/aes256-gcm"
CRATE = SCOPE / "impl/rust"
SPEC = SCOPE / "spec/Aes256GcmComposition.lean"
PROOF = HERE / "GhashSourceRefinement.lean"
PIN = ROOT / "tools/verification/probe/toolchain-candidate.json"
SOURCES = [
    PIN, SPEC, PROOF, HERE / "translate.py", Path(__file__).resolve(),
    ROOT / "tools/build/rust/Cargo.toml", ROOT / "tools/build/rust/Cargo.lock",
    CRATE / "Cargo.toml", CRATE / "src/lib.rs",
]
THEOREMS = {
    "Abc.Refine.Ghash.extracted_round_refines",
    "Abc.Refine.Ghash.extracted_loop_refines",
    "Abc.Refine.Ghash.source_multiply_returns_nist",
    "Abc.Refine.Ghash.source_hash_block_refines",
    "Abc.Refine.Ghash.source_nist_example_footer",
    "Abc.Refine.Ghash.source_length_word_refines",
    "Abc.Refine.Ghash.source_length_word_matches_nist_bytes",
    "Abc.Refine.Ghash.source_finish_tag_refines",
    "Abc.Refine.Ghash.source_hash_words_refines",
    "Abc.Refine.Ghash.source_hash_walk_padded",
    "Abc.Refine.Ghash.source_hash_tail_example",
    "Abc.Refine.Ghash.source_hash_padded_refines",
    "Abc.Refine.Ghash.source_tag_word_refines_nist",
    "Abc.Refine.Ghash.source_tag_bytes_under_aes_contract",
    "Abc.Refine.Ghash.source_tags_match_iff",
    "Abc.Refine.Ghash.source_tags_match_full_width",
    "Abc.Refine.Ghash.source_open_gate_refines",
    "Abc.Refine.Ghash.source_open_reject_preserves",
    "Abc.Refine.Ghash.source_authentication_gate_refines",
    "Abc.Refine.Ghash.source_length_limits_exact",
    "Abc.Refine.Ghash.source_length_limit_edges",
    "Abc.Refine.Ghash.source_payload_counter_refines",
    "Abc.Refine.Ghash.source_payload_counter_edges",
    "Abc.Refine.Ghash.source_admitted_counter_safe",
    "Abc.Refine.Ghash.source_counter_block_refines",
    "Abc.Refine.Ghash.source_ctr_primitives_examples",
    "Abc.Refine.Ghash.source_payload_byte_refines",
    "Abc.Refine.Ghash.source_ctr_loop_refines",
    "Abc.Refine.Ghash.source_ctr_refines_nist",
    "Abc.Refine.Ghash.source_authenticate_wiring",
    "Abc.Refine.Ghash.source_authenticate_refines_nist",
    "Abc.Refine.Ghash.source_seal_tail_authenticates_ciphertext",
    "Abc.Refine.Ghash.source_seal_with_models_refines",
    "Abc.Refine.Ghash.source_open_with_models_refines",
}
ALLOWED = {"propext", "Classical.choice", "Quot.sound"}
AXIOM_LINE = re.compile(r"^'([^']+)' (?:depends on axioms:\s*\[([^\]]*)\]|does not depend on any axioms)$", re.M)
REDUCTION = str(0xe1 << 120)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def inputs():
    return {file.relative_to(ROOT).as_posix(): digest(file) for file in SOURCES}


def execute(directory, name, command, *, cwd=ROOT, env=None, check=True):
    command = list(map(str, command))
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=240)
    trace = directory / f"{name}.log"
    trace.write_text(json.dumps(command) + "\n" + result.stdout + result.stderr, encoding="utf-8")
    if check and result.returncode:
        raise RuntimeError(f"{name} failed ({result.returncode}). See {trace}")
    return result


def emit_model(path, llbc):
    path.write_text(translate(llbc), encoding="utf-8", newline="\n")


def audit(output):
    rows = AXIOM_LINE.findall(output)
    require(len(rows) == len(THEOREMS) and {name for name, _ in rows} == THEOREMS,
            "Missing or unexpected Lean audit")
    allowed = {}
    for name, axioms in rows:
        names = [item.strip() for item in axioms.split(",") if item.strip()]
        require(set(names) <= ALLOWED, f"Unapproved axiom in {name}")
        allowed[name] = names
    return allowed


def locate(term, value):
    if term == value:
        yield term
    elif isinstance(term, list):
        for child in term:
            yield from locate(child, value)
    elif isinstance(term, dict):
        for child in term.values():
            yield from locate(child, value)


def check(options, run):
    pins = json.loads(PIN.read_text(encoding="utf-8"))
    original_inputs = inputs()
    env = {**os.environ, "RUSTUP_TOOLCHAIN": pins["rust"], "CARGO_NET_OFFLINE": "true"}

    def exec_local(name, command, *, cwd=ROOT, environment=env, check=True):
        return execute(run, name, command, cwd=cwd, env=environment, check=check)

    charon = exec_local("charon-version", [options.charon, "version"]).stdout.strip()
    require(pins["charon"] in charon, "Charon revision does not match the repository pin")
    rust_pin = exec_local("charon-toolchain", [options.charon, "toolchain-version"]).stdout.strip()
    require(rust_pin == pins["rust"], "Charon compiler selection does not match the repository pin")
    rust = exec_local("rust-version", ["rustc", "-Vv"]).stdout
    target = next(line.removeprefix("host: ") for line in rust.splitlines() if line.startswith("host: "))
    lean = exec_local("lean-version", [options.lean, "--version"]).stdout.strip()
    require(f"version {pins['lean'].split(':v')[-1]}," in lean, "Lean version does not match the repository pin")
    selections = ["--preset=aeneas", "--consts", "values", "--start-from", "crate::open_in_place",
                  "--start-from", "crate::seal_in_place"]
    cargo = ["--locked", "--offline", "--lib", "--no-default-features", "--target", target]

    def extract(label):
        directory = run / label
        directory.mkdir()
        ir = directory / "portable-api.llbc"
        exec_local(f"{label}-charon",
                   [options.charon, "cargo", *selections, "--dest-file", ir, "--", *cargo],
                   cwd=CRATE, environment={**env, "CARGO_TARGET_DIR": str(directory / "target")})
        model = directory / "GhashLlbc.lean"
        llbc = json.loads(ir.read_text(encoding="utf-8"))
        emit_model(model, llbc)
        return llbc, model, {"llbc_sha256": digest(ir), "lean_model_sha256": digest(model)}

    llbc, generated, first = extract("first")
    _, _, second = extract("second")
    require(first["lean_model_sha256"] == second["lean_model_sha256"],
            "Independent LLBC translations generated different Lean models")
    objects = run / "objects"
    objects.mkdir()

    def compile_module(name, source, output, lookup, *, check=True):
        lean_path = os.pathsep.join(map(str, lookup))
        return exec_local(name, [options.lean, f"--root={source.parent}", "-DwarningAsError=true",
                                 "-o", output / (source.stem + ".olean"), source],
                          environment={**env, "LEAN_PATH": lean_path}, check=check)

    compile_module("compile-specification", SPEC, objects, [objects])
    compile_module("compile-extraction", generated, objects, [objects])
    provenance = audit(compile_module("compile-refinement", PROOF, objects, [objects]).stdout)
    require(inputs() == original_inputs, "Source input changed during extraction or proof checking")

    def test_negative(label, diagnostic, theorem):
        mutant = run / label
        mutant.mkdir()
        source = mutant / "GhashLlbc.lean"
        emit_model(source, llbc)
        require(digest(source) != first["lean_model_sha256"], "The changed LLBC did not affect translation")
        compile_module(f"compile-{label}", source, mutant, [mutant, objects])
        rejected = compile_module(f"reject-{label}", PROOF, mutant, [mutant, objects], check=False)
        audited = dict(AXIOM_LINE.findall(rejected.stdout))
        require(rejected.returncode != 0 and diagnostic in rejected.stdout
                and "sorryAx" in audited.get(f"Abc.Refine.Ghash.{theorem}", ""),
                f"Lean did not reject the {label} at {theorem}")
        return {"status": "rejected", "changed_model_sha256": digest(source), "log": f"reject-{label}.log"}

    negative = footer_negative = tag_negative = gate_negative = length_negative = counter_negative = None
    serialization_negative = xor_negative = None
    seal_negative = None
    hash_tail_negative = None
    footer_wiring_negative = None
    if options.check_mutant:
        reduction = list(locate(llbc, ["U128", REDUCTION]))
        require(len(reduction) == 1, "Expected one extracted reduction literal")
        reduction[0][1] = str(int(REDUCTION) + 1)
        negative = test_negative("mutant", "Tactic `rfl` failed:", "extracted_round_refines")
        reduction[0][1] = REDUCTION

        footer = ScalarLoop(llbc).local_function("pack_lengths")["body"]
        footer_shift = list(locate(footer, {"Shl": "Panic"}))
        require(len(footer_shift) == 1, "Expected one checked shift in the extracted footer")
        footer_shift[0].clear()
        footer_shift[0]["Shr"] = "Panic"
        footer_negative = test_negative("footer-mutant", "Tactic `decide` proved that the proposition",
                                        "source_nist_example_footer")
        footer_shift[0].clear()
        footer_shift[0]["Shl"] = "Panic"

        closure = ScalarLoop(llbc)
        comparator = closure.local_function("tags_match")["body"]["Structured"]["body"]
        assignments = [stmt["kind"]["Assign"][1] for stmt in comparator["statements"]
                       if isinstance(stmt["kind"], dict) and "Assign" in stmt["kind"]]
        equality = [node["BinaryOp"] for node in assignments
                    if "BinaryOp" in node and node["BinaryOp"][0] == "Eq"]
        require(len(equality) == 1, "Expected one equality in the extracted comparator")
        equality[0][0] = "Ne"
        tag_negative = test_negative("tag-mutant", "Tactic `decide` proved that the proposition",
                                     "source_tags_match_full_width")
        equality[0][0] = "Eq"

        body = closure.local_function("open_in_place")["body"]["Structured"]["body"]
        (gate,) = [stmt["kind"]["Switch"]["data"] for stmt in body["statements"]
                   if isinstance(stmt["kind"], dict) and "Switch" in stmt["kind"]
                   and "Value" in stmt["kind"]["Switch"]["data"]["scrutinee"]]
        (_, explicit), = gate["branches"]
        gate["branches"][0][1], gate["fallback"] = gate["fallback"], explicit
        gate_negative = test_negative("gate-mutant", "unsolved goals", "source_open_gate_refines")
        gate["branches"][0][1], gate["fallback"] = explicit, gate["branches"][0][1]

        bounds = closure.local_function("check_lengths")["body"]["Structured"]["body"]
        comparisons = [stmt["kind"]["Assign"][1]["BinaryOp"] for stmt in bounds["statements"]
                       if isinstance(stmt["kind"], dict) and "Assign" in stmt["kind"]
                       and "BinaryOp" in stmt["kind"]["Assign"][1]]
        require(len(comparisons) == 1 and comparisons[0][0] == "Gt", "Expected the leading payload limit test")
        comparisons[0][0] = "Ge"
        length_negative = test_negative("length-mutant", "Application type mismatch", "source_length_limit_edges")
        comparisons[0][0] = "Gt"

        ctr = closure.local_function("apply_payload")["body"]
        offset = list(locate(ctr, ["U32", "2"]))
        require(len(offset) == 1, "Expected one start-counter literal in the payload loop")
        offset[0][1] = "1"
        counter_negative = test_negative("counter-mutant", "Tactic `decide` proved that the proposition",
                                         "source_payload_counter_edges")
        offset[0][1] = "2"

        encoders = [name_segments(fn) for fn in closure.functions.values()
                    if name_segments(fn)[:2] == [ident("core"), ident("num")]
                    and name_segments(fn)[-1] == ident("to_be_bytes")
                    and closure.scalar_type(name_segments(fn)[2]["Impl"]["Ty"]["skip_binder"]) == 32]
        (encoder,) = encoders
        encoder[-1] = ident("to_le_bytes")
        serialization_negative = test_negative("endianness-mutant", "Tactic `decide` proved that the proposition",
                                               "source_ctr_primitives_examples")
        encoder[-1] = ident("to_be_bytes")

        (outer,) = [body for tag, body in meaningful(ctr["Structured"]["body"]) if tag == "Loop"]
        (inner,) = [body for tag, body in meaningful(outer) if tag == "Loop"]
        (update,) = [args[1]["BinaryOp"] for tag, args in meaningful(inner)
                     if tag == "Assign" and "BinaryOp" in args[1]]
        require(update[0] == "BitXor", "Expected the extracted payload-byte XOR")
        update[0] = "BitOr"
        xor_negative = test_negative("xor-mutant", "Tactic `decide` proved that the proposition",
                                     "source_ctr_primitives_examples")
        update[0] = "BitXor"

        seal = closure.local_function("seal_in_place")["body"]["Structured"]["body"]
        authenticate_id = closure.local_function("authenticate")["def_id"]
        (auth_call,) = [args["call"] for tag, args in meaningful(seal) if tag == "Call"
                        and args["call"]["func"]["Regular"]["kind"]["Fun"] == authenticate_id]
        aad, ciphertext = map(local_operand, auth_call["args"][-2:])
        aliases = {args[0]["kind"]["Local"]: args for tag, args in meaningful(seal) if tag == "Assign"}
        require("Ref" in aliases[aad][1] and "Ref" in aliases[ciphertext][1],
                "Expected separate AAD and ciphertext reborrows")
        original = aliases[ciphertext][1]
        aliases[ciphertext][1] = aliases[aad][1]
        try:
            translate(llbc)
        except ValueError as error:
            require(str(error) == "Unexpected AES-GCM API argument flow", "Wrong seal mutation diagnostic")
            log = run / "reject-seal-buffer-mutant.log"
            log.write_text(str(error) + "\n", encoding="utf-8")
            seal_negative = {"status": "rejected", "stage": "llbc_validation", "log": log.name}
        require(seal_negative is not None, "The seal validator accepted authentication of the wrong buffer")
        aliases[ciphertext][1] = original

        padded = closure.local_function("hash_padded")["body"]["Structured"]["body"]
        (tail,) = [switch for tag, switch in meaningful(padded) if tag == "Switch"]
        (fill,) = [args["call"]["args"] for branch in tail["branches"] for tag, args in meaningful(branch)
                   if tag == "Call" and name_segments(closure.functions[args["call"]["func"]["Regular"]["kind"]["Fun"]])
                   == list(map(ident, ("core", "array", "repeat")))]
        (fill_operand,) = fill
        original, ty = closure.constant_data(fill_operand["Const"])
        require(original == {"Integer": {"Unsigned": ["U8", "0"]}}, "Expected a zero-filled GHASH partial block")
        fill[0] = {"Const": {"Value": [max(closure.constants) + 1, [{"Integer": {"Unsigned": ["U8", "1"]}}, ty]]}}
        hash_tail_negative = test_negative("ghash-tail-mutant", "Tactic `decide` proved that the proposition",
                                           "source_hash_tail_example")
        fill[0] = fill_operand

        authenticate = closure.local_function("authenticate")["body"]["Structured"]["body"]
        footer_id = closure.local_function("pack_lengths")["def_id"]
        (footer_args,) = [item["call"]["args"] for tag, item in meaningful(authenticate) if tag == "Call"
                          and item["call"]["func"]["Regular"]["kind"]["Fun"] == footer_id]
        require(len(footer_args) == 2, "Expected both length inputs in authentication")
        footer_args.reverse()
        footer_wiring_negative = test_negative("footer-wiring-mutant", "Tactic `rfl` failed:",
                                               "source_authenticate_wiring")

    return {
        "status": "source_llbc_refinement_checked", "target": target, "charon": charon,
        "rust": rust.strip(), "lean": lean, "selection": selections, "cargo": cargo,
        "source_digests": original_inputs,
        "first": first, "second": second, "theorems": provenance, "negative_check": negative,
        "footer_negative_check": footer_negative,
        "tag_negative_check": tag_negative, "gate_negative_check": gate_negative,
        "length_negative_check": length_negative, "counter_negative_check": counter_negative,
        "serialization_negative_check": serialization_negative, "xor_negative_check": xor_negative,
        "seal_negative_check": seal_negative,
        "hash_tail_negative_check": hash_tail_negative,
        "footer_wiring_negative_check": footer_wiring_negative,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--charon", default=os.environ.get("ABC_CHARON", "charon"))
    parser.add_argument("--lean", default=os.environ.get("ABC_LEAN", "lean"))
    parser.add_argument("--output", type=Path, default=ROOT / ".abc/aes256-gcm-extraction")
    parser.add_argument("--check-mutant", action="store_true")
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    run = Path(mkdtemp(prefix="run-", dir=options.output.resolve()))
    report = check(options, run)
    (run / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**report, "path": str(run)}, indent=2))


if __name__ == "__main__":
    main()

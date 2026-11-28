"""Check the RFC 8439 relation for a restricted native quarter-round source."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SPECIFICATION = HERE.parents[1] / "spec/ChaCha20QuarterRound.lean"
SOURCES = {"c": HERE / "abc_chacha20_c.c", "cpp": HERE.parent / "cpp/chacha20.cpp"}


def normalized(text):
    return re.sub(r"\s+", "", text)


def single_function(source, signature):
    matches = re.findall(re.escape(normalized(signature)) + r"\{([^{}]*)\}", source)
    if len(matches) != 1:
        raise ValueError("Expected one definition with the modeled signature")
    return matches[0]


def generated_declaration(source, language):
    if re.search(r"^\s*#\s*define\b", source, flags=re.MULTILINE):
        raise ValueError("Macro definitions are outside the modeled source subset")
    source = normalized(source)
    if language == "c":
        rotate = "static uint32_t rotate_left(uint32_t word, unsigned distance)"
        round_signature = "static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)"
        operands = r"\*([abcd])"
    else:
        if "usingWord=std::uint32_t;" not in source:
            raise ValueError("The C++ word type must have the modeled width")
        rotate = "Word rotate_left(Word word, unsigned distance) noexcept"
        round_signature = "void quarter_round(Word& a, Word& b, Word& c, Word& d) noexcept"
        operands = r"([abcd])"
    if single_function(source, rotate) != "return(word<<distance)|(word>>(32-distance));":
        raise ValueError("The rotation helper no longer matches the modeled expression")
    round_body = single_function(source, round_signature)
    if not round_body.endswith(";"):
        raise ValueError("The quarter round must end with a statement")
    statements = round_body[:-1].split(";")
    if len(statements) != 8:
        raise ValueError("The quarter round must contain eight modeled statements")
    current = {lane: f"input.{lane}" for lane in "abcd"}
    steps = []
    for index, text in enumerate(statements):
        addition = re.fullmatch(operands + r"\+=" + operands, text)
        rotation = re.fullmatch(operands + r"=rotate_left\(" + operands + r"\^" + operands + r",([1-9][0-9]?)\)", text)
        if addition is not None:
            target, right = addition.groups()
            expression = f"{current[target]} + {current[right]}"
        elif rotation is not None:
            target, left, right, distance_text = rotation.groups()
            distance = int(distance_text)
            if not 0 < distance < 32:
                raise ValueError("The shift distances must be within the unsigned word")
            value = f"({current[left]} ^^^ {current[right]})"
            expression = f"({value} <<< {distance}) ||| ({value} >>> {32 - distance})"
        else:
            raise ValueError(f"Unsupported quarter-round statement {index + 1}")
        variable = f"step{index}"
        steps.append(f"  let {variable} := {expression}")
        current[target] = variable
    output = ", ".join(current[lane] for lane in "abcd")
    return "\n".join([
        "open Abc.Spec.ChaCha20",
        "def sourceQuarterRound (input : Words) : Words :=",
        *steps,
        f"  ⟨{output}⟩",
        "theorem sourceQuarterRound_matches (input : Words) :",
        "    sourceQuarterRound input = quarterRound input := by rfl",
        "#print axioms sourceQuarterRound_matches",
        "",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=SOURCES, required=True)
    parser.add_argument("--lean", default="lean")
    arguments = parser.parse_args()
    source = SOURCES[arguments.language].read_bytes()
    generated = generated_declaration(source.decode("utf-8"), arguments.language)
    proof = SPECIFICATION.read_text(encoding="utf-8") + "\n" + generated
    with TemporaryDirectory(prefix="abc-chacha-quarter-") as directory:
        path = Path(directory) / "NativeChaChaQuarter.lean"
        path.write_text(proof, encoding="utf-8", newline="\n")
        subprocess.run([arguments.lean, "-DwarningAsError=true", str(path)], check=True, timeout=60)
    print(json.dumps({
        "status": "passed", "language": arguments.language,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "generated_lean_sha256": hashlib.sha256(proof.encode()).hexdigest(),
    }))


if __name__ == "__main__":
    main()

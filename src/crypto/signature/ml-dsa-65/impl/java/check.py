"""Check deterministic Pure ML-DSA-65 with NIST ACVP and independent OpenSSL."""

import json
import os
from pathlib import Path
import random
import sys
import tempfile


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
sys.path.insert(0, str(CRYPTO / "kdf/argon2id/impl/java"))
from bc_provider import main, run


FIXTURE = HERE.parents[1] / "spec/acvp-fips204-sample.json"
PREFIX = "3034020100300b060960864801650304031204228020"
NODE = r"""
const crypto = require('node:crypto');
const {readFileSync} = require('node:fs');
const rows = JSON.parse(readFileSync(0, 'utf8'));
const cases = rows.map(([seedDer, message, context, pubHex, fromSdk]) => {
  const privateKey = crypto.createPrivateKey({key: Buffer.from(seedDer, 'hex'), format: 'der', type: 'pkcs8'});
  const publicKey = crypto.createPublicKey(privateKey);
  const actual = publicKey.export({format: 'der', type: 'spki'}).subarray(-1952).toString('hex');
  if (actual !== pubHex) throw Error('OpenSSL public key mismatch');
  const data = Buffer.from(message, 'hex');
  const ctx = Buffer.from(context, 'hex');
  if (!crypto.verify(null, data, {key: publicKey, context: ctx}, Buffer.from(fromSdk, 'hex'))) {
    throw Error('OpenSSL did not verify the SDK signature');
  }
  return crypto.sign(null, data, {key: privateKey, context: ctx}).toString('hex');
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, cases}));
"""


def acvp_tests(invoke):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    generated = fixture["keyGen"]
    signatures = fixture["sigGen"]["cases"]
    verification = fixture["sigVer"]["cases"]
    if fixture["acvp_revision"] != "975de31eb83d87039ec88934fdc47d8c312b892d" or (
        generated["tcId"], [case["tcId"] for case in signatures], [case["tcId"] for case in verification]
    ) != (26, [41], [38, 43]):
        raise ValueError("Unexpected ACVP fixture selection")
    rows = [f'keygen:{generated["seed"]}:{generated["public_key_sha256"]}']
    for case in signatures:
        rows.append(":".join(["expanded-sign", *(case[key] for key in ("sk", "pk", "message", "context", "signature"))]))
    for case in verification:
        rows.append(":".join(["verify", *(case[key] for key in ("pk", "message", "context", "signature")),
                              str(case["testPassed"]).lower()]))
    if invoke("acvp", wire="\n".join(rows) + "\n") != str(len(rows)):
        raise ValueError("Incomplete ACVP tests")
    return generated["seed"], len(rows)


def exact_openssl(cli, rows, outputs):
    version, _ = run([cli, "version"])
    temp = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-mldsa-openssl-", dir=temp) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temp):
            raise ValueError("Temporary path is outside the established root")
        for (seed, message, context), (_, expected) in zip(rows, outputs, strict=True):
            (work / "seed.der").write_bytes(bytes.fromhex(PREFIX + seed))
            (work / "message").write_bytes(bytes.fromhex(message))
            command = [cli, "pkeyutl", "-sign", "-rawin", "-inkey", "seed.der", "-keyform", "DER",
                       "-in", "message", "-out", "reference.sig", "-pkeyopt", "deterministic:1",
                       "-pkeyopt", "message-encoding:1"]
            if context:
                command.extend(["-pkeyopt", f"hexcontext-string:{context}"])
            run(command, cwd=work)
            if (work / "reference.sig").read_bytes().hex() != expected:
                raise ValueError("Deterministic OpenSSL signature differs from the SDK")
    return version


def verify(invoke):
    seed, checked = acvp_tests(invoke)
    rng = random.Random(20465)
    rows = [(seed, rng.randbytes(m).hex(), rng.randbytes(c).hex())
            for m in (1, 64, 1024, 0) for c in (0, 2, 128, 255)]
    output = [line.split(":") for line in
              invoke("sign", wire="".join(":".join(row) + "\n" for row in rows)).splitlines()]
    samples = [[PREFIX + seed, message, context, public, signature]
               for (seed, message, context), (public, signature) in zip(rows, output, strict=True)]
    stdout, _ = run(["node", "-e", NODE], input=json.dumps(samples))
    reference = json.loads(stdout)
    wire = "".join(f"{public}:{message}:{context}:{signed}\n"
                   for (_, message, context), (public, _), signed in zip(rows, output, reference["cases"], strict=True))
    if invoke("verify", wire=wire) != str(len(rows)):
        raise ValueError("Incomplete OpenSSL-to-SDK check")
    cli = os.environ.get("ABC_MLDSA_OPENSSL")
    exact = exact_openssl(cli, rows[:12], output[:12]) if cli else None
    return {"acvp_selected": checked, "acvp_provider_expanded_sign": 1, "openssl_bidirectional": len(rows),
            "deterministic_repeats": len(rows), "openssl_exact": 12 if cli else 0, "openssl_cli": exact,
            "malformed_hint_cases": 5, "node": reference["node"], "openssl": reference["openssl"]}


if __name__ == "__main__":
    main(HERE, "ml-dsa-65", "org.allbasket.abc.signature.mldsa65", "MlDsa65", verify)

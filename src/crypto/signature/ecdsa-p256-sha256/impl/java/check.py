"""Check deterministic P-256 JARs using RFC vectors and bidirectional OpenSSL tests."""

import json
from pathlib import Path
import random
import sys


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
sys.path.insert(0, str(CRYPTO / "kdf/argon2id/impl/java"))
from bc_provider import main, run


ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
OPENSSL = HERE.parent / "go/tests/interop.mjs"


def verify(invoke):
    rng = random.Random(6979256)
    sizes = (0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 128, 1024)
    rows = [(rng.randrange(1, ORDER).to_bytes(32, "big").hex(), rng.randbytes(size).hex())
            for size in sizes for _ in range(4)]
    rows.extend([(value.to_bytes(32, "big").hex(), "42") for value in (1, ORDER - 1)])
    output = invoke("sign", wire="".join(f"{d}:{msg}\n" for d, msg in rows)).splitlines()
    samples = [{"scalar": d, "message": msg, "signature": record.split(":")[1]}
               for (d, msg), record in zip(rows, output, strict=True)]
    stdout, _ = run(["node", str(OPENSSL)], input=json.dumps(samples))
    oracle = json.loads(stdout)
    wire = ""
    for (_, msg), sdk, ref in zip(rows, output, oracle["cases"], strict=True):
        if sdk.split(":")[0] != ref["uncompressed"]:
            raise ValueError("Provider's public key did not match the independent OpenSSL output")
        wire += f'{msg}:{ref["uncompressed"]}:{ref["compressed"]}:{ref["signature"]}\n'
    if invoke("verify", wire=wire) != str(len(rows)):
        raise ValueError("Provider did not verify every independent signature")
    return {"openssl_bidirectional_cases": len(rows), "deterministic_repeats": len(rows),
            "rfc_signatures": 2, "nonce_retry_transitions": 2, "node": oracle["node"], "openssl": oracle["openssl"]}


if __name__ == "__main__":
    main(HERE, "ecdsa-p256-sha256", "org.allbasket.abc.signature.ecdsap256sha256", "EcdsaP256Sha256", verify)

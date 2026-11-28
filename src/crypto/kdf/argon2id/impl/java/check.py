"""Compare Java and Kotlin Argon2id adapters with OpenSSL and RFC 9106."""

import json
from pathlib import Path
import random
from bc_provider import main, run


HERE = Path(__file__).resolve().parent
OPENSSL = r"""
const {argon2Sync} = require('node:crypto');
const {readFileSync} = require('node:fs');
const exact = JSON.parse(readFileSync(0, 'utf8')).map(row => {
  const [memory, passes, parallelism, tagLength, ...inputs] = row;
  const [message, nonce, secret, associatedData] = inputs.map(x => Buffer.from(x, 'hex'));
  return argon2Sync('argon2id', {memory, passes, parallelism, tagLength, message, nonce,
    secret, associatedData}).toString('hex');
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, exact}));
"""
RFC = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def verify(invoke):
    rng = random.Random(910613)
    rows = []
    for lanes in range(1, 5):
        for segment in (2, 3, 4, 7, 128):
            for tag in (4, 16, 32, 64, 65):
                i = len(rows)
                memory = 4 * lanes * segment + i % (4 * lanes)
                inputs = [rng.randbytes(length).hex() for length in ((0, 1, 31, 32, 129)[i % 5],
                          (8, 16, 32)[i % 3], (0, 1, 8, 65)[i % 4], (0, 1, 12, 129)[i % 4])]
                rows.append([memory, i % 4 + 1, lanes, tag, *inputs])
    rows.append([32, 3, 4, 32, "01" * 32, "02" * 16, "03" * 8, "04" * 12])
    output, _ = run(["node", "-e", OPENSSL], input=json.dumps(rows))
    oracle = json.loads(output)
    if oracle["exact"][-1] != RFC or len(oracle["exact"]) != len(rows):
        raise ValueError("OpenSSL failed the RFC vector or returned incomplete results")
    wire = "".join(":".join(map(str, [*row, value])) + "\n"
                   for row, value in zip(rows, oracle["exact"], strict=True))
    if invoke(wire=wire) != str(len(rows)):
        raise ValueError("Unexpected Argon2id conformance case count")
    return {"openssl_cases": len(rows), "rfc_vectors": 1, "one_byte_under_budget": len(rows),
            "node": oracle["node"], "openssl": oracle["openssl"]}


if __name__ == "__main__":
    main(HERE, "argon2id", "org.allbasket.abc.kdf.argon2id", "Argon2id", verify)

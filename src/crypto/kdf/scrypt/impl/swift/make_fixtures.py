"""Generate deterministic RFC 7914 profile comparisons with OpenSSL-backed hashlib."""
from hashlib import scrypt
from itertools import product
from pathlib import Path
from random import Random
from sys import argv
import json

random_source = Random(7914)
rows = []
for cost, block_size, parallel, length in product((2, 4, 16, 32), (1, 2, 4), (1, 2, 3), (1, 32, 33, 71)):
    password = random_source.randbytes(random_source.randrange(75))
    salt = random_source.randbytes(random_source.randrange(69))
    output = scrypt(password, salt=salt, n=cost, r=block_size, p=parallel, dklen=length)
    rows.append(dict(password=password.hex(), salt=salt.hex(), cost=cost, blockSize=block_size,
                     parallel=parallel, output=output.hex()))

Path(argv[1]).write_text(json.dumps(rows) + "\n", encoding="utf-8", newline="\n")

"""Build JDK 17 PBKDF2 and verify an external consumer against JCA HMAC."""

import argparse
import json
import os
from pathlib import Path
import runpy


HERE = Path(__file__).resolve().parent
HMAC = HERE.parents[3] / "mac/hmac-sha256/impl/java"
PACKAGE = "org/allbasket/abc/kdf/pbkdf2sha256"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", default=os.environ.get("ABC_JAVA_HOME"), type=Path)
    options = parser.parse_args()
    harness = runpy.run_path(str(HMAC / "check.py"))
    test = HERE / "tests" / PACKAGE / "Pbkdf2Sha256Checks.java"
    source = HERE / "src" / PACKAGE / "Pbkdf2Sha256.java"
    libraries = [("sha256", harness["SHA"]), ("hmac-sha256", harness["HMAC"]), ("pbkdf2-sha256", source)]
    name = "org.allbasket.abc.kdf.pbkdf2sha256.Pbkdf2Sha256Checks"
    print(json.dumps(harness["check"](options.jdk, libraries, test, name), indent=2))

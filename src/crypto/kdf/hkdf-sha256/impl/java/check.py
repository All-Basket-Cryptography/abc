"""Run a JDK 17 HKDF consumer using separate Java SHA-256, HMAC and HKDF JARs."""

import argparse
import json
import os
from pathlib import Path
import runpy


HERE = Path(__file__).resolve().parent
HMAC = HERE.parents[3] / "mac/hmac-sha256/impl/java"
PACKAGE = "org/allbasket/abc/kdf/hkdfsha256"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", default=os.environ.get("ABC_JAVA_HOME"), type=Path)
    options = parser.parse_args()
    harness = runpy.run_path(str(HMAC / "check.py"))
    test = HERE / "tests" / PACKAGE / "HkdfSha256Checks.java"
    source = HERE / "src" / PACKAGE / "HkdfSha256.java"
    libraries = [("sha256", harness["SHA"]), ("hmac-sha256", harness["HMAC"]), ("hkdf-sha256", source)]
    name = "org.allbasket.abc.kdf.hkdfsha256.HkdfSha256Checks"
    print(json.dumps(harness["check"](options.jdk, libraries, test, name), indent=2))

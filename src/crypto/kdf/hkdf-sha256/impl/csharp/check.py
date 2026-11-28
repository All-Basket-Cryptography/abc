"""Check the managed HKDF implementation and its same-language dependencies."""

import argparse
import json
import os
from pathlib import Path
import runpy


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
SHA = CRYPTO / "hash/sha256/impl/csharp"
HMAC = CRYPTO / "mac/hmac-sha256/impl/csharp"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET", "dotnet"))
    options = parser.parse_args()
    harness = runpy.run_path(str(HMAC / "check.py"))
    sources = [SHA / "Sha256Hasher.cs", HMAC / "HmacSha256.cs", HERE / "HkdfSha256.cs", HERE / "tests/Program.cs"]
    test_project = HERE / "tests/HkdfSha256.Tests.csproj"
    files = [*sources, SHA / "Abc.Cryptography.Sha256.csproj", HMAC / "Abc.Cryptography.HmacSha256.csproj",
             HERE / "Abc.Cryptography.HkdfSha256.csproj", test_project]
    print(json.dumps(harness["check"](options.dotnet, files, test_project, sources), indent=2))

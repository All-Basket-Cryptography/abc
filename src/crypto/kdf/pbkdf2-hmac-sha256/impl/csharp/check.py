"""Check native C# PBKDF2 against RFC 7914 and the .NET reference implementation."""

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
    sources = [SHA / "Sha256Hasher.cs", HMAC / "HmacSha256.cs", HERE / "Pbkdf2Sha256.cs", HERE / "tests/Program.cs"]
    test_project = HERE / "tests/Pbkdf2Sha256.Tests.csproj"
    files = [*sources, SHA / "Abc.Cryptography.Sha256.csproj", HMAC / "Abc.Cryptography.HmacSha256.csproj",
             HERE / "Abc.Cryptography.Pbkdf2Sha256.csproj", test_project]
    print(json.dumps(harness["check"](options.dotnet, files, test_project, sources), indent=2))

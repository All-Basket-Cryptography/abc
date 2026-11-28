"""Task adapter for packaged SDK consumers."""

import json
import os
from pathlib import Path
import sys

from tools.release.abc_package import consumer_test, package


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[2]
    output = Path(os.environ["ABC_TASK_OUTPUT"])
    sdk = sys.argv[1]
    artifact = package(repo, sdk, output)
    result = consumer_test(repo, sdk, Path(artifact["file"]))
    (output / "consumer.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

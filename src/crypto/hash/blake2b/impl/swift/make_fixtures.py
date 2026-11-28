"""Write the published and independent BLAKE2b test corpus for Swift."""

import argparse
from pathlib import Path
import runpy


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
args = parser.parse_args()
reference = runpy.run_path(str(Path(__file__).resolve().parent.parent / "cpp" / "check.py"))
args.output.write_bytes(("\n".join(reference["fixtures"]()) + "\n").encode("ascii"))

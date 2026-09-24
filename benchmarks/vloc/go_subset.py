"""Go task ids for a VLoC measurement run.

Every Go task in the prepared workspace whose CWEs are taint-shaped or CWE-770
(the subset Frame's Go frontend targets), plus a seeded random slice of the
remaining Go tasks, printed as the comma-separated list `run.py --only` takes.
"""

import argparse
import csv
import json
import random
from pathlib import Path

TARGET = {"CWE-22", "CWE-23", "CWE-89", "CWE-78", "CWE-77", "CWE-601", "CWE-74",
          "CWE-79", "CWE-918", "CWE-770"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--extra", type=int, default=20, help="random non-target Go tasks")
    args = ap.parse_args()
    ws = Path(args.workspace).expanduser()
    manifest = ws / "manifest_subset.csv"
    if not manifest.is_file():
        manifest = ws / "vulnerability-localization-benchmark" / "data" / "manifest.csv"
    rows = [r for r in csv.DictReader(manifest.open()) if r["ecosystem"].lower() == "go"]
    target = [r["alpha_id"] for r in rows if set(json.loads(r["cwes"] or "[]")) & TARGET]
    rest = sorted(r["alpha_id"] for r in rows if r["alpha_id"] not in set(target))
    random.Random(args.seed).shuffle(rest)
    print(",".join(sorted(target) + rest[: args.extra]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

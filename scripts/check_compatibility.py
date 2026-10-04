#!/usr/bin/env python3
"""Validate the Agent Systems Lab compatibility charter."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_proof.compatibility import check_manifest, check_manifest_v2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "conformance" / "compatibility-v1.json",
    )
    parser.add_argument("--schema", choices=("v1", "v2"), default="v1")
    parser.add_argument("--json", action="store_true", help="emit the machine-readable report (the default)")
    args = parser.parse_args()
    report = check_manifest_v2(args.manifest) if args.schema == "v2" else check_manifest(args.manifest)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    if report["ok"]:
        return 0
    return 2 if args.schema == "v2" else 1


if __name__ == "__main__":
    raise SystemExit(main())

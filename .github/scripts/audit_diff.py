#!/usr/bin/env python3
"""Copy to .github/scripts/audit_diff.py in the Superset fork.

Compares scanner output on the PR head against the same scanners on the base branch.

The gate is "you did not make it worse", not "the repo is clean". An absolute gate
would fail every PR while any other advisory is still open in the backlog -- which
would mark every remediation as a CI failure regardless of merit.

    python audit_diff.py base_pip.json head_pip.json base_npm.json head_npm.json

Exits 1 if the PR introduces an advisory the base branch did not have.
"""

import json
import sys
from typing import Any


def load(path: str) -> dict[str, Any]:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def pip_ids(path: str) -> set[str]:
    data = load(path)
    return {
        f"{d['name']}:{v['id']}"
        for d in data.get("dependencies", [])
        for v in d.get("vulns", [])
    }


def npm_ids(path: str) -> set[str]:
    data = load(path)
    out: set[str] = set()
    for name, adv in (data.get("vulnerabilities") or {}).items():
        if adv.get("severity") not in ("critical", "high"):
            continue
        for via in adv.get("via", []):
            if isinstance(via, dict):
                out.add(f"{name}:{via.get('source')}")
    return out


def main() -> int:
    base_pip, head_pip, base_npm, head_npm = sys.argv[1:5]
    base = pip_ids(base_pip) | npm_ids(base_npm)
    head = pip_ids(head_pip) | npm_ids(head_npm)

    fixed, introduced = base - head, head - base

    print(f"advisories on base: {len(base)}   on this PR: {len(head)}\n")
    for a in sorted(fixed):
        print(f"  FIXED      {a}")
    for a in sorted(introduced):
        print(f"  INTRODUCED {a}")
    if not fixed and not introduced:
        print("  (no change to the advisory set)")

    if introduced:
        print(
            f"\nFAIL: this PR introduces {len(introduced)} advisory/advisories "
            f"not present on the base branch."
        )
        return 1
    if fixed:
        print(f"\nPASS: {len(fixed)} advisory/advisories cleared, none introduced.")
    else:
        print(
            "\nPASS: no advisories introduced. "
            "Note this PR did not clear one either -- if it was meant to, "
            "check that the fix actually landed in the manifest."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

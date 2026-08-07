#!/usr/bin/env python3
"""Copy to .github/scripts/open_findings.py in the Superset fork.

Turns scanner output into GitHub issues, one per finding, idempotently.
The fingerprint line in each issue body is what makes re-runs safe.
"""

import json
import os
import subprocess
import sys

MAX_NEW = int(os.getenv("MAX_NEW", "5"))
FINGERPRINT = "<!-- autoremediation-fingerprint: {} -->"

SEVERITY_ORDER = ["critical", "high", "moderate", "low", "unknown"]


def gh(*args, **kw):
    return subprocess.run(["gh", *args], capture_output=True, text=True, **kw)


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def pip_findings():
    data = load("pip-audit.json")
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            fixes = ", ".join(v.get("fix_versions") or []) or "no fixed version published"
            out.append({
                "fp": f"pip:{dep['name']}:{v['id']}",
                "severity": "high",  # pip-audit does not emit a severity field
                "title": f"[deps] {dep['name']} {dep['version']} — {v['id']}",
                "body": (
                    f"**Package:** `{dep['name']}`\n"
                    f"**Installed:** `{dep['version']}`\n"
                    f"**Advisory:** `{v['id']}`\n"
                    f"**Fixed in:** {fixes}\n"
                    f"**Manifest:** `requirements/base.txt`\n\n"
                    f"{(v.get('description') or '').strip()[:1500]}\n\n"
                    f"**Acceptance:** `pip-audit -r requirements/base.txt --no-deps` "
                    f"no longer reports `{v['id']}`, and everything importing "
                    f"`{dep['name']}` still works."
                ),
            })
    return out


def npm_findings():
    data = load("npm-audit.json")
    out = []
    for name, adv in (data.get("vulnerabilities") or {}).items():
        sev = adv.get("severity", "unknown")
        if sev not in ("critical", "high"):
            continue  # keep the backlog to things worth an engineer's attention
        via = [v for v in adv.get("via", []) if isinstance(v, dict)]
        title_detail = via[0].get("title", "vulnerability") if via else "vulnerability"
        url = via[0].get("url", "") if via else ""
        out.append({
            "fp": f"npm:{name}:{via[0].get('source') if via else sev}",
            "severity": sev,
            "title": f"[deps] superset-frontend: {name} — {title_detail}"[:120],
            "body": (
                f"**Package:** `{name}`\n"
                f"**Severity:** {sev}\n"
                f"**Range:** `{adv.get('range')}`\n"
                f"**Manifest:** `superset-frontend/package.json`\n"
                f"**Advisory:** {url}\n\n"
                f"**Acceptance:** `npm audit` in `superset-frontend` no longer reports "
                f"this advisory, and the frontend still builds."
            ),
        })
    return out


def existing_fingerprints():
    r = gh("issue", "list", "--state", "all", "--limit", "300",
           "--json", "body", "--jq", ".[].body")
    return r.stdout or ""


def main():
    findings = pip_findings() + npm_findings()
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"])
                  if f["severity"] in SEVERITY_ORDER else 99)

    seen = existing_fingerprints()
    new = [f for f in findings if FINGERPRINT.format(f["fp"]) not in seen]

    print(f"{len(findings)} findings, {len(new)} not yet tracked")

    for f in new[:MAX_NEW]:
        body = f["body"] + "\n\n" + FINGERPRINT.format(f["fp"])
        r = gh("issue", "create",
               "--title", f["title"],
               "--body", body,
               "--label", "devin:fix",
               "--label", f"severity:{f['severity']}")
        print(("created " + r.stdout.strip()) if r.returncode == 0 else
              ("FAILED " + r.stderr.strip()))

    # No silent truncation: say what we dropped.
    if len(new) > MAX_NEW:
        print(f"NOTE: {len(new) - MAX_NEW} further findings were not opened this run "
              f"(MAX_NEW={MAX_NEW}). They will be picked up by the next scan.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

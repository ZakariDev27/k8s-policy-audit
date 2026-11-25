#!/usr/bin/env python3
"""Check a live-scan JSON report from a cluster that has both demos applied."""

from __future__ import annotations

import json
import sys

INSECURE_PREFIXES = ("shop-insecure", "billing-insecure")
# Everything the insecure demo is built to trigger. API009 (unresolvable role)
# cannot occur on a live cluster, where every referenced role exists.
EXPECTED = {
    "API001", "API002", "API003", "API004", "API005", "API006", "API007", "API008",
    "STO001", "STO002", "STO003", "STO004", "STO005", "STO006", "STO007", "STO008",
    "NET001", "NET002", "NET003", "NET004", "NET005", "NET006", "NET007", "NET008",
}


def owner(finding: dict) -> str:
    """Which demo a finding belongs to: 'insecure', 'hardened' or 'cluster'."""
    for value in (finding["namespace"], finding["name"]):
        if value.startswith(INSECURE_PREFIXES):
            return "insecure"
    if finding["namespace"] == "shop" or finding["name"].startswith("shop"):
        return "hardened"
    return "cluster"


def main(path: str) -> int:
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    groups: dict[str, list[dict]] = {"insecure": [], "hardened": [], "cluster": []}
    for finding in report["findings"]:
        groups[owner(finding)].append(finding)

    failures = []
    found = {f["check_id"] for f in groups["insecure"]}
    if found != EXPECTED:
        failures.append(
            f"insecure demo: missing {sorted(EXPECTED - found)}, "
            f"unexpected {sorted(found - EXPECTED)}"
        )
    if groups["hardened"]:
        failures.append(
            "hardened demo should be clean but has: "
            + ", ".join(f"{f['check_id']} {f['resource']}" for f in groups["hardened"])
        )
    noisy = [f for f in groups["cluster"] if f["severity"] in ("medium", "high", "critical")]
    if noisy:
        failures.append(
            "findings at medium or above on the cluster's own objects: "
            + ", ".join(f"{f['check_id']} {f['resource']}" for f in noisy)
        )

    print(f"objects scanned: {report['objects_scanned']}")
    for name, items in groups.items():
        print(f"{name:>9}: {len(items)} finding(s)")
    for finding in groups["cluster"]:
        print(f"           {finding['severity']:<8} {finding['check_id']} {finding['resource']}")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if not failures:
        print("ok: live report matches expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

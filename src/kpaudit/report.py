"""Render findings as terminal text, JSON or Markdown."""

from __future__ import annotations

import json
import textwrap
from collections import Counter
from typing import Any

from . import __version__
from .checks import CHECKS
from .model import CATEGORIES, SEVERITIES, Finding

CATEGORY_TITLES = {
    "api": "API access (RBAC)",
    "storage": "Storage controls",
    "network": "Network firewall",
}
_COLORS = {
    "critical": "\033[1;35m",
    "high": "\033[1;31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
}
_RESET = "\033[0m"


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_severity = Counter(f.severity for f in findings)
    by_category = Counter(f.category for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s: by_severity.get(s, 0) for s in reversed(SEVERITIES)},
        "by_category": {c: by_category.get(c, 0) for c in CATEGORIES},
    }


def _summary_line(findings: list[Finding], suppressed: int = 0) -> str:
    counts = summarize(findings)["by_severity"]
    parts = [f"{n} {sev}" for sev, n in counts.items() if n]
    line = f"{len(findings)} finding(s)" + (": " + ", ".join(parts) if parts else "")
    if suppressed:
        line += f" ({suppressed} suppressed)"
    return line


def render_text(
    findings: list[Finding],
    source: str,
    object_count: int,
    suppressed: int = 0,
    color: bool = False,
) -> str:
    lines = [f"kpaudit {__version__}  |  source: {source}  |  {object_count} objects scanned", ""]
    if not findings:
        lines.append("No findings." + (f" ({suppressed} suppressed)" if suppressed else ""))
        return "\n".join(lines) + "\n"

    for category in CATEGORIES:
        group = [f for f in findings if f.category == category]
        if not group:
            continue
        title = f"{CATEGORY_TITLES[category]} ({len(group)})"
        lines += [title, "=" * len(title)]
        for f in group:
            label = f"{f.severity.upper():<8}"
            if color:
                label = f"{_COLORS[f.severity]}{label}{_RESET}"
            lines.append(f"{label} {f.check_id}  {f.resource}")
            lines += textwrap.wrap(f.message, 92, initial_indent="    ", subsequent_indent="    ")
            lines += textwrap.wrap(
                "Fix: " + f.remediation, 92, initial_indent="    ", subsequent_indent="         "
            )
            lines.append("")
    lines.append(_summary_line(findings, suppressed))
    return "\n".join(lines) + "\n"


def render_json(
    findings: list[Finding], source: str, object_count: int, suppressed: int = 0
) -> str:
    payload = {
        "tool": "kpaudit",
        "version": __version__,
        "source": source,
        "objects_scanned": object_count,
        "summary": summarize(findings),
        "suppressed": suppressed,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(
    findings: list[Finding], source: str, object_count: int, suppressed: int = 0
) -> str:
    lines = [
        "# Kubernetes policy audit",
        "",
        f"Source: `{source}` · {object_count} objects scanned · "
        f"{_summary_line(findings, suppressed)}",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    summary = summarize(findings)
    lines += ["| Severity | Count |", "| --- | ---: |"]
    lines += [f"| {sev} | {n} |" for sev, n in summary["by_severity"].items()]
    lines.append("")

    for category in CATEGORIES:
        group = [f for f in findings if f.category == category]
        if not group:
            continue
        lines += [
            f"## {CATEGORY_TITLES[category]}",
            "",
            "| Severity | Check | Resource | Finding | Fix |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in group:
            lines.append(
                f"| {f.severity} | {f.check_id} | `{_cell(f.resource)}` | "
                f"{_cell(f.message)} | {_cell(f.remediation)} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_check_list() -> str:
    lines = []
    for category in CATEGORIES:
        lines.append(CATEGORY_TITLES[category])
        for info in CHECKS.values():
            if info.category == category:
                lines.append(f"  {info.check_id}  up to {info.severity:<8}  {info.title}")
        lines.append("")
    return "\n".join(lines)

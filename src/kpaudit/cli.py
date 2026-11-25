"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import CHECKS, audit
from .loader import LoadError, load_cluster, load_paths
from .model import CATEGORIES, SEVERITIES, Inventory, severity_rank
from .report import render_check_list, render_json, render_markdown, render_text

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kpaudit",
        description="Audit Kubernetes API access (RBAC), storage controls and "
        "network firewall rules (NetworkPolicy). Read-only.",
    )
    parser.add_argument("--version", action="version", version=f"kpaudit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="scan a live cluster (no paths) or manifest files/directories",
    )
    scan.add_argument(
        "paths", nargs="*",
        help="manifest files or directories; omit to scan the cluster kubectl points at",
    )
    scan.add_argument("--context", help="kubectl context to use for a live scan")
    scan.add_argument("-n", "--namespace", help="only report on this namespace")
    scan.add_argument(
        "-c", "--category", action="append", choices=CATEGORIES,
        help="only run this category (repeatable)",
    )
    scan.add_argument(
        "--min-severity", choices=SEVERITIES, default="info",
        help="hide findings below this severity (default: info)",
    )
    scan.add_argument(
        "--fail-on", choices=SEVERITIES + ["never"], default="high",
        help="exit with code 2 if any finding is at or above this severity (default: high)",
    )
    scan.add_argument(
        "--ignore", action="append", default=[], metavar="ID[,ID...]",
        help="suppress these check IDs everywhere (repeatable). To suppress a check on "
        "one object, annotate it with kpaudit.io/ignore: \"ID,ID\"",
    )
    scan.add_argument(
        "-f", "--format", choices=["text", "json", "markdown"], default="text",
    )
    scan.add_argument("-o", "--output", help="write the report to this file")
    scan.add_argument(
        "--include-system", action="store_true",
        help="also audit kube-system and other system namespaces, roles and bindings",
    )

    sub.add_parser("checks", help="list every check")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "checks":
        print(render_check_list())
        return EXIT_OK

    if args.paths and args.context:
        parser.error("--context only applies to a live scan; do not combine it with paths")

    try:
        if args.paths:
            objects = load_paths(args.paths)
            source = ", ".join(args.paths)
            warnings: list[str] = []
        else:
            objects, warnings = load_cluster(context=args.context)
            source = f"cluster ({args.context or 'current context'})"
    except LoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    for warning in warnings:
        print(f"warning: could not read {warning}", file=sys.stderr)
    if not objects:
        print("error: no Kubernetes objects found in the given paths", file=sys.stderr)
        return EXIT_ERROR

    ignore = {
        part.strip().upper() for raw in args.ignore for part in raw.split(",") if part.strip()
    }
    unknown = sorted(ignore - set(CHECKS))
    if unknown:
        parser.error(f"unknown check ID(s) for --ignore: {', '.join(unknown)}")

    inventory = Inventory(objects, include_system=args.include_system)
    findings, suppressed = audit(
        inventory, categories=args.category, min_severity=args.min_severity, ignore=ignore
    )
    if args.namespace:
        # Namespace findings are cluster-scoped objects named after the namespace.
        findings = [
            f for f in findings
            if f.namespace == args.namespace
            or (f.kind == "Namespace" and f.name == args.namespace)
        ]

    if args.format == "json":
        report = render_json(findings, source, len(inventory), suppressed)
    elif args.format == "markdown":
        report = render_markdown(findings, source, len(inventory), suppressed)
    else:
        color = args.output is None and sys.stdout.isatty()
        report = render_text(findings, source, len(inventory), suppressed, color=color)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output} ({len(findings)} finding(s))", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.fail_on != "never":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in findings):
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

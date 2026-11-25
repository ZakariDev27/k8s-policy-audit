"""Check registry and runner."""

from __future__ import annotations

from dataclasses import dataclass

from ..model import Finding, Inventory, severity_rank


@dataclass(frozen=True)
class CheckInfo:
    check_id: str
    category: str
    severity: str  # highest severity the check can report
    title: str


CHECKS: dict[str, CheckInfo] = {
    c.check_id: c
    for c in [
        # API access (RBAC)
        CheckInfo("API001", "api", "critical", "Unrestricted (wildcard / cluster-admin) access is granted"),
        CheckInfo("API002", "api", "critical", "Anonymous or all-authenticated users are bound to a role"),
        CheckInfo("API003", "api", "high", "Subjects can read Secrets"),
        CheckInfo("API004", "api", "high", "Subjects can escalate privileges (escalate / bind / impersonate)"),
        CheckInfo("API005", "api", "medium", "Subjects can exec into or attach to pods"),
        CheckInfo("API006", "api", "medium", "Role uses wildcard verbs or resources"),
        CheckInfo("API007", "api", "medium", "The default service account is bound to a role"),
        CheckInfo("API008", "api", "low", "Workload mounts the default service account's API token"),
        CheckInfo("API009", "api", "info", "Binding references a role that could not be resolved"),
        # Storage controls
        CheckInfo("STO001", "storage", "critical", "Workload mounts a hostPath volume"),
        CheckInfo("STO002", "storage", "medium", "Static PersistentVolume is backed by hostPath"),
        CheckInfo("STO003", "storage", "medium", "StorageClass does not encrypt volumes"),
        CheckInfo("STO004", "storage", "medium", "Reclaim policy can destroy or leak data"),
        CheckInfo("STO005", "storage", "low", "Volume claim is shared read-write across nodes"),
        CheckInfo("STO006", "storage", "low", "Namespace has volume claims but no storage quota"),
        CheckInfo("STO007", "storage", "low", "emptyDir volume has no size limit"),
        CheckInfo("STO008", "storage", "low", "Container root filesystem is writable"),
        # Network firewall (NetworkPolicy and exposure)
        CheckInfo("NET001", "network", "high", "Namespace has no NetworkPolicy"),
        CheckInfo("NET002", "network", "low", "Namespace has no default-deny ingress policy"),
        CheckInfo("NET003", "network", "low", "Namespace has no default-deny egress policy"),
        CheckInfo("NET004", "network", "medium", "Workload is not covered by any ingress policy"),
        CheckInfo("NET005", "network", "high", "NetworkPolicy allows ingress from anywhere"),
        CheckInfo("NET006", "network", "medium", "NetworkPolicy allows egress to anywhere"),
        CheckInfo("NET007", "network", "high", "Service is exposed outside the cluster"),
        CheckInfo("NET008", "network", "high", "Workload bypasses the pod network (hostNetwork / hostPort)"),
    ]
}


def make(
    check_id: str,
    severity: str,
    kind: str,
    namespace: str,
    name: str,
    message: str,
    remediation: str,
) -> Finding:
    info = CHECKS[check_id]
    return Finding(check_id, severity, info.category, kind, namespace, name, message, remediation)


IGNORE_ANNOTATION = "kpaudit.io/ignore"


def _annotation_ignores(inventory: Inventory) -> dict[tuple[str, str, str], set[str]]:
    """Map (kind, namespace, name) to the check IDs its annotation suppresses."""
    ignores: dict[tuple[str, str, str], set[str]] = {}
    for obj in inventory.all():
        metadata = obj.get("metadata") or {}
        raw = (metadata.get("annotations") or {}).get(IGNORE_ANNOTATION)
        if not raw:
            continue
        check_ids = {part.strip().upper() for part in str(raw).split(",") if part.strip()}
        name = metadata.get("name", "")
        # Findings use "" as the namespace of cluster-scoped objects, and "default"
        # for namespaced objects written without one. Register both spellings.
        for namespace in {metadata.get("namespace") or "", metadata.get("namespace") or "default"}:
            ignores.setdefault((obj["kind"], namespace, name), set()).update(check_ids)
    return ignores


def audit(
    inventory: Inventory,
    categories: list[str] | None = None,
    min_severity: str = "info",
    ignore: set[str] | None = None,
) -> tuple[list[Finding], int]:
    """Run the checks. Returns (findings, number of findings suppressed)."""
    from . import network, rbac, storage

    modules = {"api": rbac, "storage": storage, "network": network}
    findings: list[Finding] = []
    for category, module in modules.items():
        if categories and category not in categories:
            continue
        findings.extend(module.run(inventory))

    threshold = severity_rank(min_severity)
    findings = [f for f in findings if severity_rank(f.severity) >= threshold]

    ignore = {check_id.upper() for check_id in ignore or set()}
    per_object = _annotation_ignores(inventory)
    kept = [
        f
        for f in findings
        if f.check_id not in ignore
        and f.check_id not in per_object.get((f.kind, f.namespace, f.name), set())
    ]
    kept.sort(
        key=lambda f: (-severity_rank(f.severity), f.category, f.check_id, f.namespace, f.name)
    )
    return kept, len(findings) - len(kept)


def run_checks(
    inventory: Inventory,
    categories: list[str] | None = None,
    min_severity: str = "info",
    ignore: set[str] | None = None,
) -> list[Finding]:
    return audit(inventory, categories, min_severity, ignore)[0]

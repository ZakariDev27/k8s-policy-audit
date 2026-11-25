"""Load Kubernetes objects from manifest files or from a live cluster via kubectl."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

# Everything the checks read. Fetched one resource at a time so that a
# resource the caller is not allowed to list only costs that resource.
LIVE_RESOURCES = [
    "namespaces",
    "pods",
    "deployments.apps",
    "statefulsets.apps",
    "daemonsets.apps",
    "jobs.batch",
    "cronjobs.batch",
    "services",
    "serviceaccounts",
    "networkpolicies.networking.k8s.io",
    "persistentvolumes",
    "persistentvolumeclaims",
    "storageclasses.storage.k8s.io",
    "resourcequotas",
    "roles.rbac.authorization.k8s.io",
    "rolebindings.rbac.authorization.k8s.io",
    "clusterroles.rbac.authorization.k8s.io",
    "clusterrolebindings.rbac.authorization.k8s.io",
]

MANIFEST_SUFFIXES = {".yaml", ".yml", ".json"}


class LoadError(Exception):
    pass


def _flatten(doc: Any) -> list[dict[str, Any]]:
    """Expand `kind: List` wrappers and drop anything that is not an object."""
    if not isinstance(doc, dict):
        return []
    if doc.get("kind", "").endswith("List") and isinstance(doc.get("items"), list):
        result = []
        for item in doc["items"]:
            result.extend(_flatten(item))
        return result
    if "kind" in doc and "apiVersion" in doc:
        return [doc]
    return []


def load_file(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
        docs = list(yaml.safe_load_all(text))
    except (OSError, yaml.YAMLError) as exc:
        raise LoadError(f"{path}: {exc}") from exc
    objects = []
    for doc in docs:
        objects.extend(_flatten(doc))
    return objects


def load_paths(paths: list[str]) -> list[dict[str, Any]]:
    """Load every manifest under the given files and directories."""
    objects: list[dict[str, Any]] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files = sorted(
                p for p in path.rglob("*") if p.is_file() and p.suffix in MANIFEST_SUFFIXES
            )
        elif path.is_file():
            files = [path]
        else:
            raise LoadError(f"{raw}: no such file or directory")
        for file in files:
            objects.extend(load_file(file))
    return objects


def load_cluster(
    context: str | None = None,
    namespace: str | None = None,
    kubectl: str = "kubectl",
) -> tuple[list[dict[str, Any]], list[str]]:
    """Read objects from a live cluster. Returns (objects, warnings).

    Only `kubectl get` is ever run, so the audit is read-only.
    """
    if shutil.which(kubectl) is None:
        raise LoadError(
            f"'{kubectl}' was not found on PATH. Install kubectl, or pass manifest "
            "files/directories to scan them offline."
        )
    base = [kubectl]
    if context:
        base += ["--context", context]

    objects: list[dict[str, Any]] = []
    warnings: list[str] = []
    for resource in LIVE_RESOURCES:
        cmd = base + ["get", resource, "-o", "json"]
        cmd += ["--namespace", namespace] if namespace else ["--all-namespaces"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            warnings.append(f"{resource}: kubectl timed out")
            continue
        if proc.returncode != 0:
            reason = (proc.stderr.strip().splitlines() or ["unknown error"])[-1]
            warnings.append(f"{resource}: {reason}")
            continue
        try:
            objects.extend(_flatten(json.loads(proc.stdout)))
        except json.JSONDecodeError:
            warnings.append(f"{resource}: kubectl returned output that is not JSON")

    if not objects:
        detail = "; ".join(warnings[:3])
        raise LoadError(f"Could not read anything from the cluster. {detail}")
    return objects, warnings

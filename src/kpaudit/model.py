"""Core data structures: findings, the object inventory and workload helpers."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, dataclass
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]
CATEGORIES = ["api", "storage", "network"]

SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "local-path-storage",
}

# Kinds that carry a pod template, and where the pod spec lives inside them.
_POD_SPEC_PATHS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
_POD_LABEL_PATHS = {
    "Pod": ("metadata", "labels"),
    "Deployment": ("spec", "template", "metadata", "labels"),
    "StatefulSet": ("spec", "template", "metadata", "labels"),
    "DaemonSet": ("spec", "template", "metadata", "labels"),
    "ReplicaSet": ("spec", "template", "metadata", "labels"),
    "Job": ("spec", "template", "metadata", "labels"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "metadata", "labels"),
}


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: str
    category: str
    kind: str
    namespace: str  # "" for cluster-scoped objects
    name: str
    message: str
    remediation: str

    @property
    def resource(self) -> str:
        if self.namespace:
            return f"{self.kind}/{self.namespace}/{self.name}"
        return f"{self.kind}/{self.name}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["resource"] = self.resource
        return data


@dataclass(frozen=True)
class Workload:
    """Anything that runs pods, reduced to what the checks need."""

    kind: str
    namespace: str
    name: str
    labels: dict[str, str]
    spec: dict[str, Any]

    @property
    def containers(self) -> list[dict[str, Any]]:
        return list(self.spec.get("containers") or []) + list(
            self.spec.get("initContainers") or []
        )


def _dig(obj: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = obj
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def meta(obj: dict[str, Any]) -> dict[str, Any]:
    return obj.get("metadata") or {}


def name_of(obj: dict[str, Any]) -> str:
    return meta(obj).get("name") or "<unnamed>"


def namespace_of(obj: dict[str, Any]) -> str:
    return meta(obj).get("namespace") or "default"


class Inventory:
    """All objects under audit, indexed by kind."""

    def __init__(self, objects: list[dict[str, Any]], include_system: bool = False):
        self.include_system = include_system
        self._by_kind: dict[str, list[dict[str, Any]]] = {}
        for obj in objects:
            if not isinstance(obj, dict) or "kind" not in obj:
                continue
            self._by_kind.setdefault(obj["kind"], []).append(obj)

    def __len__(self) -> int:
        return sum(len(items) for items in self._by_kind.values())

    def kinds(self) -> dict[str, int]:
        return {kind: len(items) for kind, items in sorted(self._by_kind.items())}

    def all(self) -> Iterator[dict[str, Any]]:
        for items in self._by_kind.values():
            yield from items

    def in_scope(self, namespace: str) -> bool:
        return self.include_system or namespace not in SYSTEM_NAMESPACES

    def cluster(self, kind: str) -> list[dict[str, Any]]:
        """Cluster-scoped objects of a kind."""
        return list(self._by_kind.get(kind, []))

    def namespaced(self, kind: str) -> Iterator[dict[str, Any]]:
        """Namespaced objects of a kind, honouring the system-namespace filter."""
        for obj in self._by_kind.get(kind, []):
            if self.in_scope(namespace_of(obj)):
                yield obj

    def workloads(self) -> list[Workload]:
        """Pod-running objects, without the copies a controller creates.

        On a live cluster a Deployment also shows up as a ReplicaSet and as
        Pods. Objects that have an owner are skipped so each workload is
        reported once, against the object the user actually edits.
        """
        result = []
        for kind, path in _POD_SPEC_PATHS.items():
            for obj in self.namespaced(kind):
                if meta(obj).get("ownerReferences"):
                    continue
                spec = _dig(obj, path)
                if not isinstance(spec, dict):
                    continue
                labels = _dig(obj, _POD_LABEL_PATHS[kind]) or {}
                result.append(
                    Workload(kind, namespace_of(obj), name_of(obj), dict(labels), spec)
                )
        return result


def selector_matches(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    """Evaluate a Kubernetes label selector. An empty selector matches everything."""
    if not selector:
        return True
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key = expr.get("key")
        operator = expr.get("operator")
        values = expr.get("values") or []
        if operator == "In" and labels.get(key) not in values:
            return False
        if operator == "NotIn" and labels.get(key) in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True

"""API access checks: who can do what through the Kubernetes API (RBAC)."""

from __future__ import annotations

from typing import Any

from ..model import SYSTEM_NAMESPACES, Finding, Inventory, name_of, namespace_of
from . import make

READ_VERBS = {"get", "list", "watch", "*"}
ESCALATION_VERBS = {"escalate", "bind", "impersonate"}
RBAC_RESOURCES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
PUBLIC_SUBJECTS = {
    "system:anonymous": "critical",
    "system:unauthenticated": "critical",
    "system:authenticated": "high",
}

# Built-in ClusterRoles that exist on every cluster but are usually absent
# from a manifest directory. Lets offline scans still reason about them.
BUILTIN_ROLES = {
    "cluster-admin": {"wildcard"},
    "admin": {"secrets", "exec", "escalate"},
    "edit": {"secrets", "exec"},
    "view": set(),
}


def _is_system_name(name: str) -> bool:
    return name.startswith("system:") or name.startswith("kubeadm:")


def capabilities(rules: list[dict[str, Any]]) -> set[str]:
    """Reduce a role's rules to the risky capabilities they grant."""
    caps: set[str] = set()
    for rule in rules or []:
        verbs = set(rule.get("verbs") or [])
        resources = set(rule.get("resources") or [])
        groups = set(rule.get("apiGroups") or [])
        if not resources:  # nonResourceURLs rule
            continue
        all_verbs = "*" in verbs
        all_resources = "*" in resources
        # A rule pinned to named objects is not a grant over the whole resource type.
        named = bool(rule.get("resourceNames"))
        core = "" in groups or "*" in groups
        rbac_group = "rbac.authorization.k8s.io" in groups or "*" in groups

        if all_verbs and all_resources and "*" in groups and not named:
            caps.add("wildcard")
            continue
        if all_verbs or all_resources:
            caps.add("partial-wildcard")
        reads_secrets = (all_resources or "secrets" in resources) and verbs & READ_VERBS
        if core and not named and reads_secrets:
            caps.add("secrets")
        if verbs & ESCALATION_VERBS:
            caps.add("escalate")
        if all_verbs and rbac_group and (all_resources or resources & RBAC_RESOURCES):
            caps.add("escalate")
        exec_resources = {"pods/exec", "pods/attach", "pods/*"}
        if (
            core
            and not named
            and (all_resources or resources & exec_resources)
            and verbs & {"create", "*"}
        ):
            caps.add("exec")
    return caps


def _subject_label(subject: dict[str, Any], binding_namespace: str) -> str:
    kind = subject.get("kind", "?")
    name = subject.get("name", "?")
    if kind == "ServiceAccount":
        return f"ServiceAccount {subject.get('namespace') or binding_namespace}/{name}"
    return f"{kind} {name}"


def _in_scope_subjects(
    binding: dict[str, Any], binding_namespace: str, include_system: bool
) -> list[dict[str, Any]]:
    result = []
    for subject in binding.get("subjects") or []:
        kind = subject.get("kind")
        name = subject.get("name", "")
        if include_system or name in PUBLIC_SUBJECTS:
            result.append(subject)
            continue
        system_identity = (
            kind in ("User", "Group")
            and name.startswith("system:")
            and not name.startswith("system:serviceaccounts")
        )
        system_service_account = (
            kind == "ServiceAccount"
            and (subject.get("namespace") or binding_namespace) in SYSTEM_NAMESPACES
        )
        if system_identity or system_service_account:
            continue
        result.append(subject)
    return result


def run(inventory: Inventory) -> list[Finding]:
    findings: list[Finding] = []
    cluster_roles = {name_of(r): r for r in inventory.cluster("ClusterRole")}
    roles = {
        (namespace_of(r), name_of(r)): r
        for r in inventory.cluster("Role")
    }

    bindings: list[tuple[str, str, dict[str, Any]]] = []
    for b in inventory.cluster("ClusterRoleBinding"):
        bindings.append(("ClusterRoleBinding", "", b))
    for b in inventory.namespaced("RoleBinding"):
        bindings.append(("RoleBinding", namespace_of(b), b))

    # Roles referenced by a binding, and whether any of those bindings reaches a
    # subject we audit. Roles bound only to system components are the platform's
    # business, not the cluster owner's.
    bound_roles: set[tuple[str, str, str]] = set()
    audited_roles: set[tuple[str, str, str]] = set()

    for kind, namespace, binding in bindings:
        name = name_of(binding)
        ref = binding.get("roleRef") or {}
        ref_kind, ref_name = ref.get("kind"), ref.get("name", "?")
        role_key = (ref_kind, "" if ref_kind == "ClusterRole" else namespace, ref_name)
        bound_roles.add(role_key)

        if _is_system_name(name) and not inventory.include_system:
            continue
        subjects = _in_scope_subjects(binding, namespace, inventory.include_system)
        if not subjects:
            continue
        audited_roles.add(role_key)
        who = ", ".join(_subject_label(s, namespace) for s in subjects)
        cluster_wide = kind == "ClusterRoleBinding"
        scope = "cluster-wide" if cluster_wide else f"in namespace '{namespace}'"

        if ref_kind == "ClusterRole":
            role = cluster_roles.get(ref_name)
        else:
            role = roles.get((namespace, ref_name))
        if role is not None:
            caps = capabilities(role.get("rules") or [])
        elif ref_kind == "ClusterRole" and ref_name in BUILTIN_ROLES:
            caps = set(BUILTIN_ROLES[ref_name])
        else:
            caps = set()
            findings.append(
                make(
                    "API009", "info", kind, namespace, name,
                    f"References {ref_kind} '{ref_name}', which is not among the scanned "
                    "objects, so its permissions were not evaluated.",
                    "Include the role in the scan, or delete the binding if the role is gone.",
                )
            )

        public = [s for s in subjects if s.get("name") in PUBLIC_SUBJECTS]
        if public:
            severity = max(
                (PUBLIC_SUBJECTS[s["name"]] for s in public),
                key=["high", "critical"].index,
            )
            names = ", ".join(s["name"] for s in public)
            findings.append(
                make(
                    "API002", severity, kind, namespace, name,
                    f"Grants {ref_kind} '{ref_name}' {scope} to {names}. Anyone who can reach "
                    "the API server gets these permissions.",
                    "Bind the role to named users, groups or service accounts instead.",
                )
            )

        if "wildcard" in caps:
            if public:
                severity = "critical"
            elif cluster_wide:
                severity = "high"
            else:
                severity = "medium"
            findings.append(
                make(
                    "API001", severity, kind, namespace, name,
                    f"Grants every verb on every resource {scope} (via {ref_kind} "
                    f"'{ref_name}') to: {who}.",
                    "Replace with a role listing only the verbs and resources actually needed.",
                )
            )
            # Full access already implies everything below.
            caps = set()

        if "secrets" in caps:
            findings.append(
                make(
                    "API003", "high" if cluster_wide else "medium", kind, namespace, name,
                    f"Allows reading Secrets {scope} (via {ref_kind} '{ref_name}') for: {who}.",
                    "Remove secrets from the role, or restrict it with resourceNames to the "
                    "specific Secrets required.",
                )
            )
        if "escalate" in caps:
            findings.append(
                make(
                    "API004", "high", kind, namespace, name,
                    f"Allows privilege escalation {scope} (escalate/bind/impersonate or full "
                    f"control of RBAC objects, via {ref_kind} '{ref_name}') for: {who}.",
                    "Drop escalate, bind and impersonate, and write access to RBAC objects, "
                    "unless this subject administers access control.",
                )
            )
        if "exec" in caps:
            findings.append(
                make(
                    "API005", "medium", kind, namespace, name,
                    f"Allows exec/attach into pods {scope} (via {ref_kind} '{ref_name}') "
                    f"for: {who}.",
                    "Remove pods/exec and pods/attach unless interactive access is required.",
                )
            )

        default_sas = [
            s for s in subjects
            if s.get("kind") == "ServiceAccount" and s.get("name") == "default"
        ]
        if default_sas:
            findings.append(
                make(
                    "API007", "medium", kind, namespace, name,
                    f"Binds {ref_kind} '{ref_name}' to a 'default' service account. Every pod "
                    "that does not name its own service account inherits these permissions.",
                    "Create a dedicated service account for the workload and bind that instead.",
                )
            )

    # Roles that use wildcards without being fully open.
    custom_roles = [("ClusterRole", "", r) for r in inventory.cluster("ClusterRole")]
    custom_roles += [("Role", namespace_of(r), r) for r in inventory.namespaced("Role")]
    for kind, namespace, role in custom_roles:
        name = name_of(role)
        if not inventory.include_system and (
            _is_system_name(name) or name in BUILTIN_ROLES
        ):
            continue
        role_key = (kind, namespace, name)
        if (
            not inventory.include_system
            and role_key in bound_roles
            and role_key not in audited_roles
        ):
            continue
        if "partial-wildcard" in capabilities(role.get("rules") or []):
            findings.append(
                make(
                    "API006", "medium", kind, namespace, name,
                    "Has a rule with '*' for verbs or resources. Wildcards silently grow to "
                    "cover resources added later.",
                    "List the verbs and resources explicitly.",
                )
            )

    # Workloads that carry the default service account's token.
    default_sa_automount = {
        namespace_of(sa): sa.get("automountServiceAccountToken")
        for sa in inventory.namespaced("ServiceAccount")
        if name_of(sa) == "default"
    }
    for workload in inventory.workloads():
        sa_name = workload.spec.get("serviceAccountName") or "default"
        if sa_name != "default":
            continue
        automount = workload.spec.get("automountServiceAccountToken")
        if automount is None:
            automount = default_sa_automount.get(workload.namespace)
        if automount is False:
            continue
        findings.append(
            make(
                "API008", "low", workload.kind, workload.namespace, workload.name,
                "Runs as the 'default' service account with its API token mounted. A "
                "compromised container can call the Kubernetes API with it.",
                "Set automountServiceAccountToken: false, or use a dedicated service account "
                "if the workload needs API access.",
            )
        )

    return findings

"""Network firewall checks: NetworkPolicies and exposure outside the cluster."""

from __future__ import annotations

from typing import Any

from ..model import Finding, Inventory, name_of, namespace_of, selector_matches
from . import make

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def policy_types(policy: dict[str, Any]) -> set[str]:
    spec = policy.get("spec") or {}
    declared = spec.get("policyTypes")
    if declared:
        return set(declared)
    # Kubernetes default: Ingress always, Egress only if egress rules exist.
    return {"Ingress", "Egress"} if spec.get("egress") else {"Ingress"}


def _selects_all_pods(policy: dict[str, Any]) -> bool:
    selector = (policy.get("spec") or {}).get("podSelector") or {}
    return not selector.get("matchLabels") and not selector.get("matchExpressions")


def is_default_deny(policy: dict[str, Any], direction: str) -> bool:
    spec = policy.get("spec") or {}
    rules = spec.get("ingress" if direction == "Ingress" else "egress")
    return _selects_all_pods(policy) and direction in policy_types(policy) and not rules


def _open_peers(peers: list[dict[str, Any]]) -> list[str]:
    """Describe peers in a rule that match far more than a specific workload."""
    reasons = []
    for peer in peers:
        cidr = (peer.get("ipBlock") or {}).get("cidr")
        if cidr in OPEN_CIDRS:
            reasons.append(f"ipBlock {cidr}")
        ns_selector = peer.get("namespaceSelector")
        if ns_selector is not None and not ns_selector and not peer.get("podSelector"):
            reasons.append("every namespace (empty namespaceSelector)")
    return reasons


def run(inventory: Inventory) -> list[Finding]:
    findings: list[Finding] = []

    policies: dict[str, list[dict[str, Any]]] = {}
    for policy in inventory.namespaced("NetworkPolicy"):
        policies.setdefault(namespace_of(policy), []).append(policy)

    workloads_by_ns: dict[str, list] = {}
    for workload in inventory.workloads():
        workloads_by_ns.setdefault(workload.namespace, []).append(workload)

    for namespace, workloads in sorted(workloads_by_ns.items()):
        ns_policies = policies.get(namespace, [])
        if not ns_policies:
            findings.append(
                make(
                    "NET001", "high", "Namespace", "", namespace,
                    f"Runs {len(workloads)} workload(s) with no NetworkPolicy. Every pod "
                    "accepts traffic from, and can connect to, anything in the cluster.",
                    "Add a default-deny policy, then allow only the flows each workload needs.",
                )
            )
            continue

        if not any(is_default_deny(p, "Ingress") for p in ns_policies):
            findings.append(
                make(
                    "NET002", "low", "Namespace", "", namespace,
                    "Has no default-deny ingress policy, so new workloads start out "
                    "reachable from the whole cluster.",
                    "Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress].",
                )
            )
        if not any(is_default_deny(p, "Egress") for p in ns_policies):
            findings.append(
                make(
                    "NET003", "low", "Namespace", "", namespace,
                    "Has no default-deny egress policy, so pods can connect anywhere "
                    "unless a policy selects them.",
                    "Add a NetworkPolicy with podSelector: {} and policyTypes: [Egress], "
                    "plus an explicit DNS allowance.",
                )
            )

        ingress_policies = [p for p in ns_policies if "Ingress" in policy_types(p)]
        for workload in workloads:
            covered = any(
                selector_matches((p.get("spec") or {}).get("podSelector"), workload.labels)
                for p in ingress_policies
            )
            if not covered:
                findings.append(
                    make(
                        "NET004", "medium", workload.kind, namespace, workload.name,
                        "No ingress NetworkPolicy selects this workload's pods, so all "
                        "inbound traffic is allowed.",
                        "Add a policy whose podSelector matches these pods, or a namespace "
                        "default-deny.",
                    )
                )

    for namespace, ns_policies in sorted(policies.items()):
        for policy in ns_policies:
            spec = policy.get("spec") or {}
            name = name_of(policy)
            types = policy_types(policy)

            if "Ingress" in types:
                for rule in spec.get("ingress") or []:
                    peers = rule.get("from") or []
                    ports = rule.get("ports") or []
                    if not peers:
                        if ports:
                            severity, what = "medium", "from any source on the listed ports"
                        else:
                            severity, what = "high", "from any source on any port"
                        findings.append(
                            make(
                                "NET005", severity, "NetworkPolicy", namespace, name,
                                f"Has an ingress rule with no 'from', allowing traffic {what}.",
                                "Add 'from' peers (podSelector / namespaceSelector / ipBlock) "
                                "naming the allowed clients.",
                            )
                        )
                    for reason in _open_peers(peers):
                        findings.append(
                            make(
                                "NET005", "high" if "ipBlock" in reason else "medium",
                                "NetworkPolicy", namespace, name,
                                f"Ingress rule allows traffic from {reason}.",
                                "Narrow the peer to the specific CIDRs, namespaces or pods "
                                "that need access.",
                            )
                        )

            if "Egress" in types:
                for rule in spec.get("egress") or []:
                    peers = rule.get("to") or []
                    ports = rule.get("ports") or []
                    if not peers and not ports:
                        findings.append(
                            make(
                                "NET006", "medium", "NetworkPolicy", namespace, name,
                                "Has an egress rule with no 'to' and no ports, allowing "
                                "connections to anywhere.",
                                "List the destinations and ports the pods actually use.",
                            )
                        )
                    open_cidrs = [r for r in _open_peers(peers) if "ipBlock" in r]
                    if open_cidrs and not ports:
                        findings.append(
                            make(
                                "NET006", "medium", "NetworkPolicy", namespace, name,
                                f"Egress rule allows all ports to {open_cidrs[0]}.",
                                "Restrict the CIDR or the ports.",
                            )
                        )

    for service in inventory.namespaced("Service"):
        spec = service.get("spec") or {}
        svc_type = spec.get("type", "ClusterIP")
        namespace, name = namespace_of(service), name_of(service)
        if svc_type == "LoadBalancer":
            ranges = spec.get("loadBalancerSourceRanges") or []
            if not ranges or set(ranges) & OPEN_CIDRS:
                findings.append(
                    make(
                        "NET007", "high", "Service", namespace, name,
                        "LoadBalancer service accepts traffic from any address "
                        "(no restrictive loadBalancerSourceRanges).",
                        "Set spec.loadBalancerSourceRanges to the client CIDRs, or front "
                        "the service with an ingress controller.",
                    )
                )
        elif svc_type == "NodePort":
            findings.append(
                make(
                    "NET007", "medium", "Service", namespace, name,
                    "NodePort service opens a port on every node, bypassing any "
                    "load-balancer firewall.",
                    "Use ClusterIP behind an ingress controller, or firewall the node port "
                    "range.",
                )
            )

    for workload in inventory.workloads():
        if workload.spec.get("hostNetwork") is True:
            findings.append(
                make(
                    "NET008", "high", workload.kind, workload.namespace, workload.name,
                    "Uses hostNetwork, so its pods share the node's network stack and are "
                    "not isolated by most NetworkPolicy implementations.",
                    "Remove hostNetwork unless this is a node-level agent.",
                )
            )
        host_ports = sorted(
            {
                str(port["hostPort"])
                for container in workload.containers
                for port in container.get("ports") or []
                if port.get("hostPort")
            }
        )
        if host_ports and workload.spec.get("hostNetwork") is not True:
            findings.append(
                make(
                    "NET008", "medium", workload.kind, workload.namespace, workload.name,
                    "Binds host port(s) " + ", ".join(host_ports) + " directly on the node.",
                    "Expose the workload through a Service instead of hostPort.",
                )
            )

    return findings

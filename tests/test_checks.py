from pathlib import Path

import yaml

from kpaudit.checks import CHECKS, run_checks
from kpaudit.checks.network import is_default_deny, policy_types
from kpaudit.checks.rbac import capabilities
from kpaudit.loader import load_paths
from kpaudit.model import Inventory, selector_matches, severity_rank

DEMO = Path(__file__).resolve().parent.parent / "demo"


def scan(text: str, **kwargs):
    objects = [doc for doc in yaml.safe_load_all(text) if doc]
    return run_checks(Inventory(objects, **kwargs))


def ids(findings):
    return {f.check_id for f in findings}


def test_insecure_demo_triggers_every_check_except_unresolved_role():
    findings = run_checks(Inventory(load_paths([str(DEMO / "insecure")])))
    assert ids(findings) == set(CHECKS) - {"API009"}
    assert all(f.severity in ("info", "low", "medium", "high", "critical") for f in findings)


def test_hardened_demo_is_clean():
    findings = run_checks(Inventory(load_paths([str(DEMO / "hardened")])))
    assert findings == []


def test_findings_never_exceed_registered_severity():
    findings = run_checks(Inventory(load_paths([str(DEMO / "insecure")])))
    for f in findings:
        assert severity_rank(f.severity) <= severity_rank(CHECKS[f.check_id].severity)


# --- API access -----------------------------------------------------------

def test_capabilities():
    assert capabilities([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]) == {"wildcard"}
    assert capabilities(
        [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]
    ) == {"secrets"}
    assert capabilities(
        [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}]
    ) == set()
    assert "exec" in capabilities(
        [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}]
    )
    assert "escalate" in capabilities(
        [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": ["*"]}]
    )
    assert capabilities(
        [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
    ) == set()
    assert capabilities([{"nonResourceURLs": ["/healthz"], "verbs": ["get"]}]) == set()


ANONYMOUS_ADMIN = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: oops}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects:
  - {kind: User, name: "system:anonymous", apiGroup: rbac.authorization.k8s.io}
"""


def test_anonymous_cluster_admin_is_critical():
    findings = scan(ANONYMOUS_ADMIN)
    by_id = {f.check_id: f for f in findings}
    assert by_id["API001"].severity == "critical"
    assert by_id["API002"].severity == "critical"
    # Full access is reported once, not again as secrets/exec/escalate.
    assert ids(findings) == {"API001", "API002"}


def test_system_bindings_are_skipped_unless_requested():
    manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: cluster-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects:
  - {kind: Group, name: "system:masters", apiGroup: rbac.authorization.k8s.io}
"""
    assert scan(manifest) == []
    assert "API001" in ids(scan(manifest, include_system=True))


def test_namespaced_secret_reader_is_medium_and_unknown_role_is_reported():
    manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader, namespace: team}
rules:
  - {apiGroups: [""], resources: ["secrets"], verbs: ["get"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: reader, namespace: team}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: reader}
subjects:
  - {kind: User, name: alice, apiGroup: rbac.authorization.k8s.io}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ghost, namespace: team}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: missing}
subjects:
  - {kind: User, name: bob, apiGroup: rbac.authorization.k8s.io}
"""
    findings = scan(manifest)
    by_id = {f.check_id: f for f in findings}
    assert by_id["API003"].severity == "medium"
    assert by_id["API009"].name == "ghost"


# --- Storage --------------------------------------------------------------

POD_TEMPLATE = """
apiVersion: v1
kind: Pod
metadata: {{name: p, namespace: team, labels: {{app: p}}}}
spec:
  serviceAccountName: p
  containers:
    - name: c
      image: x
      securityContext: {{readOnlyRootFilesystem: true}}
  volumes:
    - name: v
      {volume}
"""


def test_hostpath_severity_depends_on_path():
    plain = scan(POD_TEMPLATE.format(volume="hostPath: {path: /data/cache}"))
    sensitive = scan(POD_TEMPLATE.format(volume="hostPath: {path: /var/run/docker.sock}"))
    root = scan(POD_TEMPLATE.format(volume="hostPath: {path: /}"))
    sev = lambda fs: next(f.severity for f in fs if f.check_id == "STO001")
    assert sev(plain) == "high"
    assert sev(sensitive) == "critical"
    assert sev(root) == "critical"


def test_emptydir_size_limit():
    assert "STO007" in ids(scan(POD_TEMPLATE.format(volume="emptyDir: {}")))
    assert "STO007" not in ids(scan(POD_TEMPLATE.format(volume="emptyDir: {sizeLimit: 1Gi}")))


def test_storage_class_encryption():
    template = """
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {{name: sc}}
provisioner: {provisioner}
reclaimPolicy: Retain
parameters: {params}
"""
    assert "STO003" in ids(scan(template.format(provisioner="ebs.csi.aws.com", params="{}")))
    assert scan(
        template.format(provisioner="ebs.csi.aws.com", params='{encrypted: "true"}')
    ) == []
    local = scan(template.format(provisioner="rancher.io/local-path", params="{}"))
    assert [(f.check_id, f.severity) for f in local] == [("STO003", "info")]


# --- Network --------------------------------------------------------------

def test_selector_matching():
    labels = {"app": "api", "tier": "web"}
    assert selector_matches({}, labels)
    assert selector_matches(None, labels)
    assert selector_matches({"matchLabels": {"app": "api"}}, labels)
    assert not selector_matches({"matchLabels": {"app": "db"}}, labels)
    expr = lambda op, key="tier", values=("web",): {
        "matchExpressions": [{"key": key, "operator": op, "values": list(values)}]
    }
    assert selector_matches(expr("In"), labels)
    assert not selector_matches(expr("NotIn"), labels)
    assert selector_matches(expr("Exists"), labels)
    assert not selector_matches(expr("DoesNotExist"), labels)
    assert selector_matches(expr("DoesNotExist", key="zone"), labels)


def test_policy_type_defaults_and_default_deny():
    deny = {"spec": {"podSelector": {}}}
    assert policy_types(deny) == {"Ingress"}
    assert is_default_deny(deny, "Ingress")
    assert not is_default_deny(deny, "Egress")
    with_egress = {"spec": {"podSelector": {}, "egress": [{}]}}
    assert policy_types(with_egress) == {"Ingress", "Egress"}
    allow_all = {"spec": {"podSelector": {}, "ingress": [{}]}}
    assert not is_default_deny(allow_all, "Ingress")
    scoped = {"spec": {"podSelector": {"matchLabels": {"app": "x"}}}}
    assert not is_default_deny(scoped, "Ingress")


def test_allow_all_ingress_rule_and_port_only_rule():
    template = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: np, namespace: team}}
spec:
  podSelector: {{}}
  ingress:
    - {rule}
"""
    wide_open = scan(template.format(rule="{}"))
    ports_only = scan(template.format(rule="{ports: [{port: 443}]}"))
    sev = lambda fs: next(f.severity for f in fs if f.check_id == "NET005")
    assert sev(wide_open) == "high"
    assert sev(ports_only) == "medium"


def test_controller_owned_pods_are_not_double_counted():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: team}
spec:
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: c, image: x}]}
---
apiVersion: v1
kind: Pod
metadata:
  name: web-abc
  namespace: team
  labels: {app: web}
  ownerReferences: [{kind: ReplicaSet, name: web-1}]
spec: {containers: [{name: c, image: x}]}
"""
    findings = scan(manifest)
    assert {f.kind for f in findings if f.check_id == "API008"} == {"Deployment"}
    assert "Runs 1 workload(s)" in next(f.message for f in findings if f.check_id == "NET001")


def test_system_namespaces_are_skipped_by_default():
    manifest = POD_TEMPLATE.format(volume="hostPath: {path: /etc}").replace(
        "namespace: team", "namespace: kube-system"
    )
    assert scan(manifest) == []
    assert "STO001" in ids(scan(manifest, include_system=True))


def test_loadbalancer_source_ranges():
    template = """
apiVersion: v1
kind: Service
metadata: {{name: s, namespace: team}}
spec:
  type: LoadBalancer
  loadBalancerSourceRanges: {ranges}
"""
    assert "NET007" in ids(scan(template.format(ranges="[]")))
    assert "NET007" in ids(scan(template.format(ranges='["0.0.0.0/0"]')))
    assert scan(template.format(ranges='["10.0.0.0/8"]')) == []


# --- Noise control ----------------------------------------------------------

def test_fresh_kind_cluster_baseline_is_quiet():
    """Objects modelled on what a new kind cluster contains (hand-written, not a dump).

    Only the node-local StorageClass should be reported; platform RBAC, kube-system
    workloads and controller-owned pods must stay out of the report.
    """
    fixture = Path(__file__).parent / "fixtures" / "kind-baseline.yaml"
    findings = run_checks(Inventory(load_paths([str(fixture)])))
    assert sorted((f.check_id, f.severity, f.resource) for f in findings) == [
        ("STO003", "info", "StorageClass/standard"),
        ("STO004", "low", "StorageClass/standard"),
    ]


def test_resource_names_limit_a_grant():
    rule = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}
    assert capabilities([rule]) == {"secrets"}
    assert capabilities([{**rule, "resourceNames": ["tls-cert"]}]) == set()


def test_wildcard_role_bound_only_to_system_subjects_is_not_reported():
    role = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: provisioner}
rules:
  - {apiGroups: [""], resources: ["persistentvolumes"], verbs: ["*"]}
"""
    binding = """
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: provisioner}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: provisioner}
subjects:
  - {kind: ServiceAccount, name: provisioner, namespace: %s}
"""
    assert ids(scan(role)) == {"API006"}  # unbound: someone can still bind it
    assert scan(role + binding % "kube-system") == []
    assert ids(scan(role + binding % "team")) == {"API006"}


def test_suppression_by_flag_and_by_annotation():
    manifest = POD_TEMPLATE.format(volume="emptyDir: {}")
    assert "STO007" in ids(scan(manifest))

    objects = [doc for doc in yaml.safe_load_all(manifest) if doc]
    assert "STO007" not in ids(run_checks(Inventory(objects), ignore={"sto007"}))

    objects[0]["metadata"]["annotations"] = {"kpaudit.io/ignore": "STO007, NET001"}
    findings = run_checks(Inventory(objects))
    # The annotation is on the Pod, so it silences the Pod's finding only;
    # NET001 is reported against the Namespace and stays.
    assert "STO007" not in ids(findings)
    assert "NET001" in ids(findings)

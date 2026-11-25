# k8s-policy-audit

[![CI](https://github.com/ZakariDev27/k8s-policy-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ZakariDev27/k8s-policy-audit/actions/workflows/ci.yml)

`kpaudit` is a read-only command-line tool that audits a Kubernetes cluster, or a
folder of manifests, in three areas:

| Area | What it evaluates |
| --- | --- |
| **API access** | RBAC: which users, groups and service accounts can do what through the Kubernetes API |
| **Storage controls** | Volumes, StorageClasses, claims, reclaim policies and quotas |
| **Network firewall** | NetworkPolicies, and anything exposed outside the cluster |

Every finding names the object, explains the risk and says how to fix it. The exit
code makes the tool usable as a CI gate, so a risky change fails the pipeline
before it reaches a cluster.

![kpaudit scanning the insecure demo](docs/images/scan-insecure.svg)

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Demos](#demos)
- [Usage](#usage)
- [Checks](#checks)
- [Suppressing findings](#suppressing-findings)
- [Use as a CI gate](#use-as-a-ci-gate)
- [How it works](#how-it-works)
- [Testing](#testing)
- [Scope and limits](#scope-and-limits)

## Install

Requires Python 3.10 or newer. Live scans also need `kubectl` on your `PATH`.

```bash
git clone https://github.com/ZakariDev27/k8s-policy-audit.git
cd k8s-policy-audit
pip install -e .
```

## Quick start

```bash
kpaudit scan demo/insecure      # deliberately misconfigured: 34 findings, exit code 2
kpaudit scan demo/hardened      # the same app locked down: no findings, exit code 0
kpaudit scan                    # the cluster your kubectl currently points at
```

A live scan only ever runs `kubectl get`, so it cannot change anything. The
[demos](#demos) below walk through each of these.

`demo/insecure` is deliberately misconfigured. Apply it only to a throwaway cluster.

## Demos

Four demos, each reproducible from this repository. The first three need no
cluster. All output shown is real output from the tool.

| Demo | Shows | Needs |
| --- | --- | --- |
| [1. Catch a misconfigured app](#demo-1-catch-a-misconfigured-app) | What a scan reports and how findings read | Python |
| [2. Harden an app in three steps](#demo-2-harden-an-app-in-three-steps) | Findings dropping from 10 to 0 as each area is fixed | Python |
| [3. Gate a pipeline](#demo-3-gate-a-pipeline) | Exit codes, filters and reports for CI | Python |
| [4. Audit a live cluster](#demo-4-audit-a-live-cluster) | The same checks against a running kind cluster | kind, kubectl |

### Demo 1: Catch a misconfigured app

`demo/insecure` is a small shop application with the kinds of mistakes that reach
real clusters: cluster-admin for a default service account, a role handed to every
authenticated user, a container mounting the node's `/var/run`, an unencrypted
StorageClass, no NetworkPolicy, and a LoadBalancer open to the internet.

```bash
kpaudit scan demo/insecure                       # all 34 findings
kpaudit scan demo/insecure --min-severity high   # the 9 that matter most (screenshot above)
kpaudit scan demo/insecure -c storage            # one area at a time
kpaudit scan demo/hardened                       # the same app, locked down
```

![kpaudit scanning the hardened demo](docs/images/scan-hardened.svg)

The full report for the insecure demo, in the Markdown format the tool writes, is
in [docs/sample-report.md](docs/sample-report.md).

### Demo 2: Harden an app in three steps

`demo/walkthrough` holds one application, `notes`, at four stages. Each file is the
complete application, so you can scan any stage on its own and diff two stages to
see exactly what changed.

| Stage | File | What changed | API | Storage | Network | Total |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 0 | `0-insecure.yaml` | Starting point | 4 | 4 | 2 | **10** |
| 1 | `1-network.yaml` | Default-deny policy, scoped allow rule, NodePort replaced by ClusterIP | 4 | 4 | 0 | **8** |
| 2 | `2-storage.yaml` | Storage quota, single-writer claim, emptyDir size limit, read-only root filesystem | 4 | 0 | 0 | **4** |
| 3 | `3-api.yaml` | Dedicated service account with no API token; broad `edit` binding removed | 0 | 0 | 0 | **0** |

![Findings dropping across the walkthrough stages](docs/images/walkthrough.svg)

Run it yourself:

```bash
kpaudit scan demo/walkthrough/0-insecure.yaml -c network
```

```
Network firewall (2)
====================
HIGH     NET001  Namespace/notes
    Runs 1 workload(s) with no NetworkPolicy. Every pod accepts traffic from, and can
    connect to, anything in the cluster.
    Fix: Add a default-deny policy, then allow only the flows each workload needs.

MEDIUM   NET007  Service/notes/notes
    NodePort service opens a port on every node, bypassing any load-balancer firewall.
    Fix: Use ClusterIP behind an ingress controller, or firewall the node port range.

2 finding(s): 1 high, 1 medium
```

See the fix, then confirm it worked:

```bash
diff demo/walkthrough/0-insecure.yaml demo/walkthrough/1-network.yaml
kpaudit scan demo/walkthrough/1-network.yaml -c network      # No findings.
```

Repeat for `-c storage` with stage 2 and `-c api` with stage 3.

### Demo 3: Gate a pipeline

The exit code is the gate: `2` when anything is at or above `--fail-on`, `0` otherwise.

```bash
kpaudit scan demo/walkthrough/0-insecure.yaml; echo "exit code: $?"                    # 2
kpaudit scan demo/walkthrough/3-api.yaml; echo "exit code: $?"                         # 0

# Stage 2 has medium findings left: it passes the default gate, fails a stricter one
kpaudit scan demo/walkthrough/2-storage.yaml > /dev/null; echo "exit code: $?"           # 0
kpaudit scan demo/walkthrough/2-storage.yaml --fail-on medium > /dev/null; echo "exit code: $?"   # 2

# Reports for people and for machines
kpaudit scan demo/insecure -f markdown -o audit-report.md
kpaudit scan demo/insecure -f json | python3 -c "import json,sys; print(json.load(sys.stdin)['summary'])"
```

This repository gates itself the same way: [its CI workflow](.github/workflows/ci.yml)
requires the hardened demo to pass and the insecure demo to fail on every push.

### Demo 4: Audit a live cluster

```bash
kind create cluster --name audit
kubectl apply -f demo/insecure/ -f demo/hardened/
kubectl -n shop rollout status deployment/api

kpaudit scan                      # everything
kpaudit scan -n shop              # hardened namespace: No findings.
kpaudit scan -n shop-insecure     # exit code 2

kind delete cluster --name audit
```

`scripts/e2e.sh` runs this demo unattended and checks the result. This is its
output from CI, on a kind cluster holding 260 objects:

```
==> Deploying demo workloads to context: kind-kpaudit-e2e
==> Waiting for the hardened demo to become ready (proves the secure config runs)
deployment "api" successfully rolled out
partitioned roll out complete: 1 new pods have been updated...
==> Live scan
Report written to /tmp/kpaudit-live.n0kR5Q.json (36 finding(s))
objects scanned: 260
 insecure: 34 finding(s)
 hardened: 0 finding(s)
  cluster: 2 finding(s)
           low      STO004 StorageClass/standard
           info     STO003 StorageClass/standard
ok: live report matches expectations
==> Exit codes
ok: hardened namespace passes with --fail-on low
ok: insecure namespace fails the gate (exit 2)
==> End-to-end test passed
```

The two findings on the cluster itself are kind's default StorageClass, which
stores volumes unencrypted on the node and deletes data with the claim. Both are
correct, and expected on a local cluster.

## Usage

```
kpaudit scan [PATHS...] [options]

  PATHS                 manifest files or directories; omit to scan the live cluster
  --context NAME        kubectl context for a live scan
  -n, --namespace NS    only report findings in one namespace
  -c, --category CAT    api | storage | network (repeatable)
  --min-severity SEV    hide findings below info | low | medium | high | critical
  --fail-on SEV         exit 2 if any finding is at or above SEV
                        (default: high; "never" to always exit 0)
  --ignore ID[,ID...]   suppress check IDs everywhere (repeatable)
  -f, --format FMT      text | json | markdown
  -o, --output FILE     write the report to a file
  --include-system      also audit kube-system and platform roles and bindings

kpaudit checks          list every check
```

| Exit code | Meaning |
| --- | --- |
| `0` | No finding at or above the `--fail-on` severity |
| `1` | The scan could not run (bad path, no `kubectl`, cluster unreachable) |
| `2` | At least one finding at or above the `--fail-on` severity |

`-n` filters the report to findings on objects in that namespace. Cluster-scoped
objects (ClusterRoleBindings, StorageClasses, PersistentVolumes) are left out of a
namespace-filtered report.

## Checks

Severity is assigned per finding; the table shows the highest each check can reach.

### API access (RBAC)

| ID | Up to | Finding |
| --- | --- | --- |
| API001 | critical | Unrestricted (wildcard / cluster-admin) access is granted |
| API002 | critical | Anonymous or all-authenticated users are bound to a role |
| API003 | high | Subjects can read Secrets |
| API004 | high | Subjects can escalate privileges (escalate / bind / impersonate) |
| API005 | medium | Subjects can exec into or attach to pods |
| API006 | medium | Role uses wildcard verbs or resources |
| API007 | medium | The default service account is bound to a role |
| API008 | low | Workload mounts the default service account's API token |
| API009 | info | Binding references a role that could not be resolved |

Permissions are evaluated at the binding, where a role meets a subject, so the
report says who holds an access, not only that a risky role exists. A grant made by
a ClusterRoleBinding is rated higher than the same grant inside one namespace.

### Storage controls

| ID | Up to | Finding |
| --- | --- | --- |
| STO001 | critical | Workload mounts a hostPath volume (critical for `/`, `/etc`, `/var/run` and similar) |
| STO002 | medium | Static (hand-made) PersistentVolume is backed by hostPath |
| STO003 | medium | StorageClass does not encrypt volumes |
| STO004 | medium | Reclaim policy can destroy or leak data |
| STO005 | low | Volume claim is shared read-write across nodes |
| STO006 | low | Namespace has volume claims but no storage quota |
| STO007 | low | emptyDir volume has no size limit |
| STO008 | low | Container root filesystem is writable |

### Network firewall

| ID | Up to | Finding |
| --- | --- | --- |
| NET001 | high | Namespace has no NetworkPolicy |
| NET002 | low | Namespace has no default-deny ingress policy |
| NET003 | low | Namespace has no default-deny egress policy |
| NET004 | medium | Workload is not covered by any ingress policy |
| NET005 | high | NetworkPolicy allows ingress from anywhere |
| NET006 | medium | NetworkPolicy allows egress to anywhere |
| NET007 | high | Service is exposed outside the cluster (LoadBalancer / NodePort) |
| NET008 | high | Workload bypasses the pod network (hostNetwork / hostPort) |

## Suppressing findings

Some findings are accepted risks: a node agent needs `hostNetwork`, a public site
needs an open LoadBalancer. Record that decision where reviewers will see it, on
the object itself:

```yaml
metadata:
  annotations:
    kpaudit.io/ignore: "NET007"        # comma-separated check IDs
```

The annotation applies to findings reported against that object. To silence a check
everywhere, use `--ignore NET002,NET003`. Reports state how many findings were
suppressed, so suppression is never silent.

## Use as a CI gate

```yaml
jobs:
  policy-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install git+https://github.com/ZakariDev27/k8s-policy-audit
      - run: kpaudit scan k8s/ --fail-on high
```

For Helm or Kustomize, render first and scan the output:

```bash
helm template my-release ./chart > rendered.yaml && kpaudit scan rendered.yaml
kubectl kustomize overlays/prod > rendered.yaml && kpaudit scan rendered.yaml
```

## How it works

```
manifests ─┐
           ├─> loader ─> Inventory ─> checks (api, storage, network) ─> report ─> exit code
kubectl ───┘
```

- **One code path for files and clusters.** A live scan runs `kubectl get <resource>
  -o json` for each resource type and feeds the result through the same checks as
  files on disk. Whatever authentication `kubectl` already has (kubeconfig, cloud
  exec plugins, OIDC) works without extra setup, and offline tests exercise the
  same logic a live scan uses.
- **Least privilege.** The tool needs only `get`/`list`. If the account cannot list
  a resource type, that type is skipped with a warning and the rest of the audit
  still runs.
- **Each workload is reported once.** On a live cluster a Deployment also exists as
  a ReplicaSet and Pods. Objects with an owner are skipped, so findings point at the
  object you actually edit.
- **Platform noise is filtered.** System namespaces, `system:` and `kubeadm:`
  bindings, roles bound only to system components, and dynamically provisioned
  volumes are left out by default. `--include-system` turns that off.

```
src/kpaudit/
  cli.py            argument parsing and exit codes
  loader.py         manifests and kubectl -> list of objects
  model.py          Finding, Inventory, workload and label-selector helpers
  report.py         text / JSON / Markdown output
  checks/
    __init__.py     check registry, runner and suppression
    rbac.py         API access
    storage.py      storage controls
    network.py      network firewall
demo/               insecure, hardened and step-by-step walkthrough manifests
docs/               sample report and README screenshots
scripts/e2e.sh      end-to-end test against a real cluster
tests/              unit and CLI tests
```

Adding a check: register it in `checks/__init__.py`, emit it from the matching
module with `make(...)`, add a failing case to `demo/insecure` and a test.

## Testing

```bash
pip install -e ".[dev]"
make lint        # ruff
make test        # unit and CLI tests, no cluster needed
make e2e         # end-to-end, needs a throwaway cluster as the current context
```

- **Unit and CLI tests** cover each check, label-selector evaluation, NetworkPolicy
  defaulting, suppression, output formats, exit codes and the `kubectl` loader.
- **`scripts/e2e.sh`** applies both demos to a real cluster, waits for the hardened
  workloads to become ready, runs a live scan and asserts that the insecure demo
  triggers every check, the hardened demo triggers none, and the cluster's own
  objects produce nothing at medium or above.
- **The demos are tested.** The walkthrough's finding counts, the sample report
  and the README screenshots are regenerated in the test suite and must match.
- **CI** runs lint and tests on Python 3.10 and 3.13, and runs the end-to-end test
  on a kind cluster for every push and pull request.

## Scope and limits

- This is a static configuration audit. It reads what NetworkPolicies say; it does
  not send traffic to prove the CNI plugin enforces them.
- RBAC evaluation covers Roles, ClusterRoles and their bindings. A rule limited by
  `resourceNames` is treated as a narrow grant. Access granted outside RBAC
  (webhook authorizers, cloud IAM mappings such as EKS access entries) is not seen.
- StorageClass encryption (STO003) is evaluated for the AWS EBS and EFS CSI drivers
  and for node-local provisioners. Other provisioners are not evaluated.
- In manifest scans, the built-in ClusterRoles `cluster-admin`, `admin`, `edit` and
  `view` are understood even though they are not in the files. A binding to any
  other role that is not in the scanned files is reported as API009.
- Pod-level hardening beyond storage and network (privileged containers,
  capabilities, image provenance) is out of scope; Pod Security Admission covers it.

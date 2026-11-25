"""Storage control checks: volumes, storage classes, claims and quotas."""

from __future__ import annotations

from ..model import Finding, Inventory, name_of, namespace_of
from . import make

# Host paths that hand over the node (or the cluster) when mounted.
SENSITIVE_HOST_PATHS = [
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
    "/run",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/etcd",
    "/var/log",
]

# Provisioners that only encrypt when told to: provisioner -> (parameter, expected value)
ENCRYPTION_PARAMS = {
    "ebs.csi.aws.com": ("encrypted", "true"),
    "kubernetes.io/aws-ebs": ("encrypted", "true"),
    "efs.csi.aws.com": ("encryptInTransit", "true"),
}
# Provisioners that write straight to a node's disk.
NODE_LOCAL_PROVISIONERS = {
    "rancher.io/local-path",
    "k8s.io/minikube-hostpath",
    "kubernetes.io/no-provisioner",
    "kubernetes.io/host-path",
}


def _is_sensitive(path: str) -> bool:
    normalized = "/" + path.strip("/")
    if normalized == "/":
        return True
    return any(
        normalized == p or normalized.startswith(p + "/") for p in SENSITIVE_HOST_PATHS
    )


def run(inventory: Inventory) -> list[Finding]:
    findings: list[Finding] = []

    for workload in inventory.workloads():
        for volume in workload.spec.get("volumes") or []:
            vol_name = volume.get("name", "?")
            if "hostPath" in volume:
                path = (volume["hostPath"] or {}).get("path", "")
                sensitive = _is_sensitive(path)
                findings.append(
                    make(
                        "STO001", "critical" if sensitive else "high",
                        workload.kind, workload.namespace, workload.name,
                        f"Volume '{vol_name}' mounts host path '{path}'"
                        + (", which exposes node or cluster internals." if sensitive
                           else ", tying the pod to the node's filesystem."),
                        "Use a PersistentVolumeClaim, ConfigMap or Secret instead. If the host "
                        "path is unavoidable, mount it readOnly and as narrowly as possible.",
                    )
                )
            if "emptyDir" in volume and not (volume["emptyDir"] or {}).get("sizeLimit"):
                findings.append(
                    make(
                        "STO007", "low", workload.kind, workload.namespace, workload.name,
                        f"emptyDir volume '{vol_name}' has no sizeLimit and can fill the "
                        "node's disk.",
                        "Set emptyDir.sizeLimit.",
                    )
                )

        writable = [
            c.get("name", "?")
            for c in workload.containers
            if (c.get("securityContext") or {}).get("readOnlyRootFilesystem") is not True
        ]
        if writable:
            findings.append(
                make(
                    "STO008", "low", workload.kind, workload.namespace, workload.name,
                    "Containers with a writable root filesystem: " + ", ".join(writable) + ".",
                    "Set securityContext.readOnlyRootFilesystem: true and mount explicit "
                    "volumes for the paths that need writes.",
                )
            )

    for pv in inventory.cluster("PersistentVolume"):
        spec = pv.get("spec") or {}
        annotations = (pv.get("metadata") or {}).get("annotations") or {}
        # A dynamically provisioned volume is the StorageClass's doing and is
        # reported there (STO003); only hand-made hostPath volumes are flagged.
        dynamic = "pv.kubernetes.io/provisioned-by" in annotations
        if "hostPath" in spec and not dynamic:
            path = (spec["hostPath"] or {}).get("path", "")
            findings.append(
                make(
                    "STO002", "medium", "PersistentVolume", "", name_of(pv),
                    f"Backed by host path '{path}'. Data lives unencrypted on one node and "
                    "is readable by anything with access to that node.",
                    "Use a CSI-provisioned volume for anything beyond single-node testing.",
                )
            )
        if spec.get("persistentVolumeReclaimPolicy") == "Recycle":
            findings.append(
                make(
                    "STO004", "medium", "PersistentVolume", "", name_of(pv),
                    "Uses the deprecated 'Recycle' reclaim policy, which reuses the volume "
                    "for the next claim after a basic scrub.",
                    "Use Retain (keep data for manual cleanup) or Delete with dynamic "
                    "provisioning.",
                )
            )

    for sc in inventory.cluster("StorageClass"):
        provisioner = sc.get("provisioner", "")
        params = {k: str(v).lower() for k, v in (sc.get("parameters") or {}).items()}
        if provisioner in ENCRYPTION_PARAMS:
            key, expected = ENCRYPTION_PARAMS[provisioner]
            if params.get(key.lower(), params.get(key)) != expected:
                findings.append(
                    make(
                        "STO003", "medium", "StorageClass", "", name_of(sc),
                        f"Provisioner '{provisioner}' is not asked to encrypt "
                        f"(parameters.{key} is not \"{expected}\").",
                        f"Set parameters.{key}: \"{expected}\" on the StorageClass.",
                    )
                )
        elif provisioner in NODE_LOCAL_PROVISIONERS:
            findings.append(
                make(
                    "STO003", "info", "StorageClass", "", name_of(sc),
                    f"Provisioner '{provisioner}' stores volumes unencrypted on the node's "
                    "local disk. Normal for kind/minikube; not suitable for sensitive data.",
                    "On a real cluster, use a CSI driver with encryption at rest.",
                )
            )
        if sc.get("reclaimPolicy", "Delete") == "Delete":
            findings.append(
                make(
                    "STO004", "low", "StorageClass", "", name_of(sc),
                    "reclaimPolicy is Delete, so deleting a claim permanently deletes its "
                    "data.",
                    "Use reclaimPolicy: Retain for classes that hold data you cannot recreate.",
                )
            )

    quota_namespaces = set()
    for quota in inventory.namespaced("ResourceQuota"):
        hard = (quota.get("spec") or {}).get("hard") or {}
        if any(k == "persistentvolumeclaims" or k.endswith("requests.storage") for k in hard):
            quota_namespaces.add(namespace_of(quota))

    claim_namespaces: dict[str, int] = {}
    for pvc in inventory.namespaced("PersistentVolumeClaim"):
        namespace = namespace_of(pvc)
        claim_namespaces[namespace] = claim_namespaces.get(namespace, 0) + 1
        modes = (pvc.get("spec") or {}).get("accessModes") or []
        if "ReadWriteMany" in modes:
            findings.append(
                make(
                    "STO005", "low", "PersistentVolumeClaim", namespace, name_of(pvc),
                    "Requests ReadWriteMany, so any pod in the namespace on any node can "
                    "mount and modify the same data.",
                    "Use ReadWriteOnce or ReadWriteOncePod unless shared writes are required.",
                )
            )
    # Claims created by StatefulSet templates count too.
    for sts in inventory.namespaced("StatefulSet"):
        if (sts.get("spec") or {}).get("volumeClaimTemplates"):
            namespace = namespace_of(sts)
            claim_namespaces[namespace] = claim_namespaces.get(namespace, 0) + 1

    for namespace, count in sorted(claim_namespaces.items()):
        if namespace not in quota_namespaces:
            findings.append(
                make(
                    "STO006", "low", "Namespace", "", namespace,
                    f"Has {count} source(s) of volume claims but no ResourceQuota limiting "
                    "requests.storage or persistentvolumeclaims.",
                    "Add a ResourceQuota with requests.storage and persistentvolumeclaims "
                    "limits.",
                )
            )

    return findings

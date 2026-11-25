# Kubernetes policy audit

Source: `demo/insecure` · 15 objects scanned · 34 finding(s): 1 critical, 8 high, 11 medium, 14 low

| Severity | Count |
| --- | ---: |
| critical | 1 |
| high | 8 |
| medium | 11 |
| low | 14 |
| info | 0 |

## API access (RBAC)

| Severity | Check | Resource | Finding | Fix |
| --- | --- | --- | --- | --- |
| high | API001 | `ClusterRoleBinding/shop-insecure-admin` | Grants every verb on every resource cluster-wide (via ClusterRole 'cluster-admin') to: ServiceAccount shop-insecure/default. | Replace with a role listing only the verbs and resources actually needed. |
| high | API002 | `ClusterRoleBinding/shop-insecure-ops-everyone` | Grants ClusterRole 'shop-insecure-ops' cluster-wide to system:authenticated. Anyone who can reach the API server gets these permissions. | Bind the role to named users, groups or service accounts instead. |
| high | API003 | `ClusterRoleBinding/shop-insecure-ops-everyone` | Allows reading Secrets cluster-wide (via ClusterRole 'shop-insecure-ops') for: Group system:authenticated. | Remove secrets from the role, or restrict it with resourceNames to the specific Secrets required. |
| high | API004 | `ClusterRoleBinding/shop-insecure-ops-everyone` | Allows privilege escalation cluster-wide (escalate/bind/impersonate or full control of RBAC objects, via ClusterRole 'shop-insecure-ops') for: Group system:authenticated. | Drop escalate, bind and impersonate, and write access to RBAC objects, unless this subject administers access control. |
| medium | API005 | `ClusterRoleBinding/shop-insecure-ops-everyone` | Allows exec/attach into pods cluster-wide (via ClusterRole 'shop-insecure-ops') for: Group system:authenticated. | Remove pods/exec and pods/attach unless interactive access is required. |
| medium | API006 | `ClusterRole/shop-insecure-ops` | Has a rule with '*' for verbs or resources. Wildcards silently grow to cover resources added later. | List the verbs and resources explicitly. |
| medium | API007 | `ClusterRoleBinding/shop-insecure-admin` | Binds ClusterRole 'cluster-admin' to a 'default' service account. Every pod that does not name its own service account inherits these permissions. | Create a dedicated service account for the workload and bind that instead. |
| low | API008 | `Deployment/billing-insecure/invoices` | Runs as the 'default' service account with its API token mounted. A compromised container can call the Kubernetes API with it. | Set automountServiceAccountToken: false, or use a dedicated service account if the workload needs API access. |
| low | API008 | `Deployment/billing-insecure/ledger` | Runs as the 'default' service account with its API token mounted. A compromised container can call the Kubernetes API with it. | Set automountServiceAccountToken: false, or use a dedicated service account if the workload needs API access. |
| low | API008 | `Deployment/shop-insecure/api` | Runs as the 'default' service account with its API token mounted. A compromised container can call the Kubernetes API with it. | Set automountServiceAccountToken: false, or use a dedicated service account if the workload needs API access. |
| low | API008 | `Deployment/shop-insecure/cache` | Runs as the 'default' service account with its API token mounted. A compromised container can call the Kubernetes API with it. | Set automountServiceAccountToken: false, or use a dedicated service account if the workload needs API access. |

## Storage controls

| Severity | Check | Resource | Finding | Fix |
| --- | --- | --- | --- | --- |
| critical | STO001 | `Deployment/shop-insecure/api` | Volume 'runtime' mounts host path '/var/run', which exposes node or cluster internals. | Use a PersistentVolumeClaim, ConfigMap or Secret instead. If the host path is unavoidable, mount it readOnly and as narrowly as possible. |
| medium | STO002 | `PersistentVolume/shop-insecure-uploads` | Backed by host path '/tmp/shop-insecure-uploads'. Data lives unencrypted on one node and is readable by anything with access to that node. | Use a CSI-provisioned volume for anything beyond single-node testing. |
| medium | STO003 | `StorageClass/shop-insecure-fast` | Provisioner 'ebs.csi.aws.com' is not asked to encrypt (parameters.encrypted is not "true"). | Set parameters.encrypted: "true" on the StorageClass. |
| medium | STO004 | `PersistentVolume/shop-insecure-uploads` | Uses the deprecated 'Recycle' reclaim policy, which reuses the volume for the next claim after a basic scrub. | Use Retain (keep data for manual cleanup) or Delete with dynamic provisioning. |
| low | STO004 | `StorageClass/shop-insecure-fast` | reclaimPolicy is Delete, so deleting a claim permanently deletes its data. | Use reclaimPolicy: Retain for classes that hold data you cannot recreate. |
| low | STO005 | `PersistentVolumeClaim/shop-insecure/uploads` | Requests ReadWriteMany, so any pod in the namespace on any node can mount and modify the same data. | Use ReadWriteOnce or ReadWriteOncePod unless shared writes are required. |
| low | STO006 | `Namespace/shop-insecure` | Has 1 source(s) of volume claims but no ResourceQuota limiting requests.storage or persistentvolumeclaims. | Add a ResourceQuota with requests.storage and persistentvolumeclaims limits. |
| low | STO007 | `Deployment/shop-insecure/api` | emptyDir volume 'scratch' has no sizeLimit and can fill the node's disk. | Set emptyDir.sizeLimit. |
| low | STO008 | `Deployment/billing-insecure/invoices` | Containers with a writable root filesystem: invoices. | Set securityContext.readOnlyRootFilesystem: true and mount explicit volumes for the paths that need writes. |
| low | STO008 | `Deployment/billing-insecure/ledger` | Containers with a writable root filesystem: ledger. | Set securityContext.readOnlyRootFilesystem: true and mount explicit volumes for the paths that need writes. |
| low | STO008 | `Deployment/shop-insecure/api` | Containers with a writable root filesystem: api. | Set securityContext.readOnlyRootFilesystem: true and mount explicit volumes for the paths that need writes. |
| low | STO008 | `Deployment/shop-insecure/cache` | Containers with a writable root filesystem: redis. | Set securityContext.readOnlyRootFilesystem: true and mount explicit volumes for the paths that need writes. |

## Network firewall

| Severity | Check | Resource | Finding | Fix |
| --- | --- | --- | --- | --- |
| high | NET001 | `Namespace/shop-insecure` | Runs 2 workload(s) with no NetworkPolicy. Every pod accepts traffic from, and can connect to, anything in the cluster. | Add a default-deny policy, then allow only the flows each workload needs. |
| high | NET005 | `NetworkPolicy/billing-insecure/invoices-allow` | Ingress rule allows traffic from ipBlock 0.0.0.0/0. | Narrow the peer to the specific CIDRs, namespaces or pods that need access. |
| high | NET007 | `Service/shop-insecure/api` | LoadBalancer service accepts traffic from any address (no restrictive loadBalancerSourceRanges). | Set spec.loadBalancerSourceRanges to the client CIDRs, or front the service with an ingress controller. |
| high | NET008 | `Deployment/billing-insecure/ledger` | Uses hostNetwork, so its pods share the node's network stack and are not isolated by most NetworkPolicy implementations. | Remove hostNetwork unless this is a node-level agent. |
| medium | NET004 | `Deployment/billing-insecure/ledger` | No ingress NetworkPolicy selects this workload's pods, so all inbound traffic is allowed. | Add a policy whose podSelector matches these pods, or a namespace default-deny. |
| medium | NET005 | `NetworkPolicy/billing-insecure/invoices-allow` | Ingress rule allows traffic from every namespace (empty namespaceSelector). | Narrow the peer to the specific CIDRs, namespaces or pods that need access. |
| medium | NET006 | `NetworkPolicy/billing-insecure/invoices-allow` | Has an egress rule with no 'to' and no ports, allowing connections to anywhere. | List the destinations and ports the pods actually use. |
| medium | NET007 | `Service/shop-insecure/cache` | NodePort service opens a port on every node, bypassing any load-balancer firewall. | Use ClusterIP behind an ingress controller, or firewall the node port range. |
| medium | NET008 | `Deployment/shop-insecure/api` | Binds host port(s) 8080 directly on the node. | Expose the workload through a Service instead of hostPort. |
| low | NET002 | `Namespace/billing-insecure` | Has no default-deny ingress policy, so new workloads start out reachable from the whole cluster. | Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress]. |
| low | NET003 | `Namespace/billing-insecure` | Has no default-deny egress policy, so pods can connect anywhere unless a policy selects them. | Add a NetworkPolicy with podSelector: {} and policyTypes: [Egress], plus an explicit DNS allowance. |

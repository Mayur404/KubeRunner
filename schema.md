# Cluster Graph JSON Schema

This document defines the JSON schema for `cluster-graph.json` — the intermediate representation of a Kubernetes cluster used by the Kubernetes Attack Path Visualizer.

---

## Top-Level Structure

```json
{
  "metadata": { ... },
  "nodes":    [ ... ],
  "edges":    [ ... ]
}
```

---

## `metadata` Object

| Field | Type | Required | Description |
|---|---|---|---|
| `cluster_name` | string | Yes | Human-readable cluster name |
| `scan_timestamp` | string (ISO 8601) | Yes | Time the data was collected |
| `version` | string | Yes | Schema version (currently `"1.0"`) |
| `description` | string | No | Free-text description of the dataset |

**Example:**
```json
{
  "cluster_name": "prod-cluster-01",
  "scan_timestamp": "2026-03-09T21:00:00Z",
  "version": "1.0",
  "description": "Synthetic cluster with 6 pre-planted attack paths"
}
```

---

## `nodes` Array

Each object in the `nodes` array represents a Kubernetes entity.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | **Yes** | Unique node identifier used in `edges` (kebab-case) |
| `type` | string | **Yes** | Entity type — see **Node Types** below |
| `name` | string | **Yes** | Display name of the entity |
| `namespace` | string | **Yes** | Kubernetes namespace or logical grouping |
| `risk_score` | number | **Yes** | Base risk score from 0.0 to 10.0 (CVSS scale) |
| `cve` | string | No | CVE identifier if a known vulnerability exists |
| `labels` | object | No | Kubernetes-style key-value label map |
| `description` | string | No | Human-readable description of the entity |
| `is_crown_jewel` | boolean | No | `true` marks this node as a sensitive target |

### Node Types

| Type | Description | Example |
|---|---|---|
| `Internet` | Public internet entry point | Public IP, external user |
| `Service` | Kubernetes Service object | LoadBalancer, NodePort |
| `Pod` | Kubernetes Pod (workload) | webapp-front, ci-runner |
| `ServiceAccount` | Kubernetes RBAC identity | webapp-sa |
| `Role` | Namespace-scoped RBAC Role | secret-reader |
| `ClusterRole` | Cluster-wide RBAC Role | cluster-admin |
| `Secret` | Kubernetes Secret | db-credentials |
| `ConfigMap` | Kubernetes ConfigMap | app-config |
| `Database` | External or managed database | production-db |
| `User` | Human IAM user | dev-1 |

**Example Node:**
```json
{
  "id": "webapp-pod",
  "type": "Pod",
  "name": "webapp-front",
  "namespace": "default",
  "risk_score": 7.5,
  "cve": "CVE-2021-44228",
  "labels": { "app": "webapp", "tier": "frontend" },
  "description": "Frontend pod vulnerable to Log4Shell",
  "is_crown_jewel": false
}
```

---

## `edges` Array

Each object in the `edges` array represents a directed trust relationship between two nodes.

| Field | Type | Required | Description |
|---|---|---|---|
| `source` | string | **Yes** | ID of the source node (the entity that holds the privilege) |
| `target` | string | **Yes** | ID of the target node (the entity being accessed or controlled) |
| `relationship` | string | **Yes** | Type of trust relationship — see **Relationship Types** below |
| `weight` | number | **Yes** | Exploitability cost (1.0 = trivial, 10.0 = severe). Lower weight = easier for attacker. |

### Relationship Types

| Relationship | Direction | Description |
|---|---|---|
| `routes-traffic-to` | Service → Pod | Network routing |
| `uses-service-account` | Pod → ServiceAccount | Pod identity binding |
| `bound-to` | ServiceAccount → Role | RBAC role binding |
| `can-read` | Role → Secret/ConfigMap | Permission to read resources |
| `can-write` | Role → ConfigMap | Permission to write resources |
| `grants-admin-to` | Role → ServiceAccount | Admin privilege grant (may create loops) |
| `grants-full-access-to` | ClusterRole → Pod | Full cluster access |
| `can-exec` | User → Pod | User can `kubectl exec` into pod |
| `can-impersonate` | Pod → ServiceAccount | Pod can impersonate another identity |
| `authenticates-to` | Secret → Database | Credential grants database access |
| `stores-state-in` | APIServer → etcd | Internal cluster state relationship |
| `mounts-hostpath` | Pod → Secret | Dangerous host path volume mount |
| `accesses-backup-of` | Secret → Database | Backup credential access |

**Example Edge:**
```json
{
  "source": "webapp-sa",
  "target": "role-secret-reader",
  "relationship": "bound-to",
  "weight": 1.0
}
```

---

## Edge Weight Guidelines

| Weight Range | Meaning | Example |
|---|---|---|
| 1.0 – 2.0 | Trivially exploitable | Standard RBAC binding, exec permission |
| 3.0 – 5.0 | Moderately privileged step | Network hop, indirect impersonation |
| 6.0 – 7.9 | Significant CVE involved | Container escape (CVSS ~7.x) |
| 8.0 – 9.9 | Critical CVE / very high impact | RCE, privilege escalation |
| 10.0 | Crown jewel access granted | DB auth, cluster-admin grant |

---

## Attack Path Logic

The tool constructs attack paths by following directed edges from a **source** node (e.g., `public-internet`) to a **target** node (e.g., `production-db`). Each traversal represents a step an attacker could take in a real-world lateral movement scenario.

```
public-internet
  --[routes-traffic-to]--> ingress-nginx (CVE-2023-5044, CVSS 9.8)
  --[routes-traffic-to]--> webapp-pod   (CVE-2021-44228, CVSS 7.5)
  --[uses-service-account]--> webapp-sa
  --[bound-to]--> role-secret-reader
  --[can-read]--> db-secret
  --[authenticates-to]--> production-db   [CROWN JEWEL]
```

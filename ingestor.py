"""
ingestor.py — Kubernetes Cluster State Ingestor
================================================
Handles loading cluster state from two sources:
  1. Offline  — a JSON file conforming to the cluster-graph schema (mock or exported)
  2. Live     — real kubectl calls (requires a configured kubeconfig/kubectl on PATH)

Schema Reference: See schema.md
"""

import json
import os
import subprocess
import sys
from typing import Dict, Any, List, Optional

# ---------------------------------------------------------------------------
# MOCK CVE DATABASE  (replaces live NVD API calls for offline/demo mode)
# ---------------------------------------------------------------------------
MOCK_CVE_DB: Dict[str, Dict[str, Any]] = {
    "CVE-2023-5044":  {"cvss": 9.8, "description": "Nginx Ingress Controller RCE via annotation injection"},
    "CVE-2021-44228": {"cvss": 10.0, "description": "Log4Shell — JNDI injection leading to remote code execution"},
    "CVE-2024-1234":  {"cvss": 8.1, "description": "Unpatched container runtime privilege escalation"},
    "CVE-2022-23648": {"cvss": 7.5, "description": "containerd container escape — host filesystem access"},
    "CVE-2023-48795": {"cvss": 9.8, "description": "Terrapin SSH downgrade attack — etcd cluster compromise"},
    "CVE-2022-21698": {"cvss": 6.5, "description": "Prometheus client_golang path traversal via histogram labels"},
    "CVE-2024-5321":  {"cvss": 8.8, "description": "SSRF + SSTI in sidecar proxy leading to code execution"},
}


class KubernetesIngestor:
    """
    Loads Kubernetes cluster state from an offline JSON graph file or a live cluster.

    Parameters
    ----------
    use_mock : bool
        If True, loads from a local JSON file (default: mock-cluster-graph.json).
    mock_file_path : str
        Path to the JSON cluster graph file.
    """

    def __init__(self, use_mock: bool = True, mock_file_path: str = "mock-cluster-graph.json"):
        self.use_mock = use_mock
        self.mock_file_path = mock_file_path

    # ------------------------------------------------------------------
    # Public Interface
    # ------------------------------------------------------------------

    def load_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Returns the cluster graph data as a dict with keys 'nodes' and 'edges'.
        Optionally enriches nodes with CVE metadata from the mock CVE database.
        """
        if self.use_mock:
            data = self._load_from_json()
        else:
            data = self._load_from_live_cluster()

        self._enrich_cve_data(data)
        return data

    # ------------------------------------------------------------------
    # Offline JSON Loader
    # ------------------------------------------------------------------

    def _load_from_json(self) -> Dict[str, Any]:
        if not os.path.exists(self.mock_file_path):
            raise FileNotFoundError(
                f"Cluster graph file not found: '{self.mock_file_path}'\n"
                "Please provide a valid JSON file with --filepath or use --mock for the built-in dataset."
            )
        with open(self.mock_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        print(f"    [+] Loaded {len(nodes)} nodes and {len(edges)} edges from '{self.mock_file_path}'.")
        return data

    # ------------------------------------------------------------------
    # Live Cluster Loader via kubectl
    # ------------------------------------------------------------------

    def _load_from_live_cluster(self) -> Dict[str, Any]:
        """
        Queries live cluster via kubectl and constructs a graph dict.
        Requires kubectl configured with cluster access.
        """
        print("    [+] Querying live cluster via kubectl...")
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        node_index: Dict[str, bool] = {}

        def _get(resource: str) -> Optional[dict]:
            try:
                result = subprocess.run(
                    ["kubectl", "get", resource, "-A", "-o", "json"],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    print(f"    [!] kubectl error for '{resource}': {result.stderr.strip()}", file=sys.stderr)
                    return None
                return json.loads(result.stdout)
            except FileNotFoundError:
                print("    [!] kubectl not found on PATH. Run with --mock to use offline data.", file=sys.stderr)
                sys.exit(1)
            except subprocess.TimeoutExpired:
                print(f"    [!] kubectl timed out querying '{resource}'.", file=sys.stderr)
                return None

        def _add_node(node_id: str, node_type: str, name: str, namespace: str, risk: float = 0.0,
                      cve: str = None, labels: dict = None, description: str = "") -> None:
            if node_id not in node_index:
                node_index[node_id] = True
                nodes.append({
                    "id": node_id, "type": node_type, "name": name,
                    "namespace": namespace, "risk_score": risk,
                    "cve": cve, "labels": labels or {}, "description": description
                })

        def _add_edge(source: str, target: str, relationship: str, weight: float = 1.0) -> None:
            if source in node_index and target in node_index:
                edges.append({"source": source, "target": target,
                              "relationship": relationship, "weight": weight})

        # ---- Pods ----
        pods_data = _get("pods")
        if pods_data:
            for item in pods_data.get("items", []):
                meta = item.get("metadata", {})
                pod_id = f"pod-{meta.get('namespace','default')}-{meta.get('name','unknown')}"
                sa_name = item.get("spec", {}).get("serviceAccountName", "default")
                ns = meta.get("namespace", "default")
                sa_id = f"sa-{ns}-{sa_name}"
                _add_node(pod_id, "Pod", meta.get("name", ""), ns)
                _add_node(sa_id, "ServiceAccount", sa_name, ns)
                _add_edge(pod_id, sa_id, "uses-service-account", 1.0)

        # ---- RoleBindings ----
        rb_data = _get("rolebindings")
        if rb_data:
            for item in rb_data.get("items", []):
                meta = item.get("metadata", {})
                ns = meta.get("namespace", "default")
                role_ref = item.get("roleRef", {})
                role_id = f"role-{ns}-{role_ref.get('name','unknown')}"
                role_kind = role_ref.get("kind", "Role")
                _add_node(role_id, role_kind, role_ref.get("name", ""), ns)
                for subj in item.get("subjects", []):
                    s_name = subj.get("name", "unknown")
                    s_ns = subj.get("namespace", ns)
                    s_kind = subj.get("kind", "ServiceAccount")
                    s_id = f"sa-{s_ns}-{s_name}"
                    _add_node(s_id, s_kind, s_name, s_ns)
                    _add_edge(s_id, role_id, "bound-to", 1.0)

        # ---- ClusterRoleBindings ----
        crb_data = _get("clusterrolebindings")
        if crb_data:
            for item in crb_data.get("items", []):
                role_ref = item.get("roleRef", {})
                cr_id = f"clusterrole-{role_ref.get('name','unknown')}"
                _add_node(cr_id, "ClusterRole", role_ref.get("name", ""), "cluster-wide")
                for subj in item.get("subjects", []):
                    s_name = subj.get("name", "unknown")
                    s_ns = subj.get("namespace", "default")
                    s_id = f"sa-{s_ns}-{s_name}"
                    _add_node(s_id, subj.get("kind", "ServiceAccount"), s_name, s_ns)
                    _add_edge(s_id, cr_id, "bound-to", 1.0)

        # ---- Secrets ----
        secrets_data = _get("secrets")
        if secrets_data:
            for item in secrets_data.get("items", []):
                meta = item.get("metadata", {})
                ns = meta.get("namespace", "default")
                sec_id = f"secret-{ns}-{meta.get('name','unknown')}"
                _add_node(sec_id, "Secret", meta.get("name", ""), ns)

        print(f"    [+] Live scrape complete: {len(nodes)} nodes, {len(edges)} edges discovered.")

        return {
            "metadata": {
                "cluster_name": "live-cluster",
                "scan_timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "version": "1.0",
                "description": "Live cluster scrape via kubectl"
            },
            "nodes": nodes,
            "edges": edges
        }

    # ------------------------------------------------------------------
    # CVE Enrichment
    # ------------------------------------------------------------------

    def _enrich_cve_data(self, data: Dict[str, Any]) -> None:
        """
        Enriches node risk_score with CVSS data from the local CVE database
        whenever a CVE ID is present on the node.
        """
        for node in data.get("nodes", []):
            cve_id = node.get("cve")
            if cve_id and cve_id in MOCK_CVE_DB:
                entry = MOCK_CVE_DB[cve_id]
                # Override risk_score with official CVSS score
                node["risk_score"] = entry["cvss"]
                node["cve_description"] = entry["description"]


if __name__ == "__main__":
    ingestor = KubernetesIngestor(use_mock=True)
    data = ingestor.load_data()
    print(f"Nodes: {len(data['nodes'])}  Edges: {len(data['edges'])}")

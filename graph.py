"""
graph.py — Cluster Graph Builder
=================================
Constructs a NetworkX DiGraph from parsed cluster JSON data.
Each node stores entity metadata and each directed edge stores
the relationship type and an exploitability weight.

Edge Weight Convention
----------------------
Lower weight  = easier/cheaper for an attacker to traverse this link.
A weight of 1.0 represents a trivially exploitable trust relationship
(e.g., a Service Account to Role binding with no extra barrier).
Higher weights (up to 10.0) represent routes guarded by known CVEs or
highly privileged steps that, despite their impact, are the *target*
rather than the barrier.

For Dijkstra (shortest path), we invert exploitability to find the
path of *least resistance*: a low-weight edge is easy to exploit.
"""

import networkx as nx
from typing import Dict, Any, List, Tuple


class ClusterGraph:
    """
    Builds and holds the NetworkX DiGraph representing the Kubernetes cluster.

    The graph supports:
    - Efficient BFS, DFS, and Dijkstra traversal via NetworkX
    - Node attribute lookup (type, name, namespace, risk_score, cve)
    - Edge attribute lookup (relationship, weight)
    """

    # Node types considered as public entry points (attack sources)
    SOURCE_TYPES = frozenset(["Internet", "Service"])

    # Node types considered as crown jewels (attack targets)
    CROWN_JEWEL_TYPES = frozenset(["Database", "Secret"])

    def __init__(self, raw_data: Dict[str, Any]):
        self.raw_data = raw_data
        self.metadata = raw_data.get("metadata", {})
        self.graph = nx.DiGraph()
        self._build_graph()

    # ------------------------------------------------------------------
    # Graph Construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> None:
        """Populates nodes and directed edges from the raw JSON data."""

        for node in self.raw_data.get("nodes", []):
            node_id = node.get("id")
            if not node_id:
                continue
            self.graph.add_node(
                node_id,
                type=node.get("type", "Unknown"),
                name=node.get("name", node_id),
                namespace=node.get("namespace", "default"),
                risk_score=float(node.get("risk_score", 0.0)),
                cve=node.get("cve"),
                cve_description=node.get("cve_description", ""),
                labels=node.get("labels", {}),
                description=node.get("description", ""),
                is_crown_jewel=node.get("is_crown_jewel", False),
            )

        for edge in self.raw_data.get("edges", []):
            source = edge.get("source")
            target = edge.get("target")
            if not source or not target:
                continue
            if source not in self.graph or target not in self.graph:
                continue  # Skip edges with undefined endpoints

            self.graph.add_edge(
                source,
                target,
                relationship=edge.get("relationship", "connected-to"),
                weight=float(edge.get("weight", 1.0)),
            )

    # ------------------------------------------------------------------
    # Graph Accessors
    # ------------------------------------------------------------------

    def get_graph(self) -> nx.DiGraph:
        """Returns the underlying NetworkX DiGraph."""
        return self.graph

    def get_source_nodes(self) -> List[str]:
        """Returns all nodes that act as public entry points."""
        return [n for n, d in self.graph.nodes(data=True) if d.get("type") in self.SOURCE_TYPES]

    def get_crown_jewel_nodes(self) -> List[str]:
        """Returns all nodes flagged as crown jewels (sensitive targets)."""
        crown = [n for n, d in self.graph.nodes(data=True)
                 if d.get("is_crown_jewel") or d.get("type") in self.CROWN_JEWEL_TYPES]
        return crown

    def node_label(self, node_id: str) -> str:
        """Returns a human-readable label for a node."""
        d = self.graph.nodes.get(node_id, {})
        return f"{d.get('type', 'Unknown')}:{d.get('name', node_id)}"

    def summary(self) -> Dict[str, Any]:
        """Returns a brief summary of the graph statistics."""
        return {
            "cluster_name": self.metadata.get("cluster_name", "unknown"),
            "scan_timestamp": self.metadata.get("scan_timestamp", "unknown"),
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "is_dag": nx.is_directed_acyclic_graph(self.graph),
            "source_nodes": self.get_source_nodes(),
            "crown_jewels": self.get_crown_jewel_nodes(),
        }


if __name__ == "__main__":
    from ingestor import KubernetesIngestor
    ingestor = KubernetesIngestor(use_mock=True)
    data = ingestor.load_data()
    cg = ClusterGraph(data)
    s = cg.summary()
    print(f"Cluster: {s['cluster_name']}  |  Nodes: {s['nodes']}  |  Edges: {s['edges']}")
    print(f"Is DAG: {s['is_dag']}")
    print(f"Crown Jewels: {s['crown_jewels']}")
    print(f"Entry Points: {s['source_nodes']}")

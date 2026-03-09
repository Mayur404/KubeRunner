"""
analyzer.py — Security Graph Algorithms
=========================================
Implements all three mandatory algorithms and the Critical Node analysis:

  Algorithm 1  Blast Radius Detection      BFS up to N hops
  Algorithm 2  Shortest Path (Attack Route) Dijkstra's algorithm on edge weights
  Algorithm 3  Circular Permission Detection DFS cycle detection
  Task 4       Critical Node Identification  Subgraph path-count comparison
"""

import networkx as nx
from typing import Dict, List, Optional, Set, Tuple


class SecurityAnalyzer:
    """
    Core security analysis engine. Operates on a pre-built NetworkX DiGraph.

    All methods are read-only — the underlying graph is never mutated.
    """

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    # ==================================================================
    # Algorithm 1 — Blast Radius Detection (BFS)
    # ==================================================================

    def blast_radius_bfs(self, start_node: str, max_hops: int = 3) -> Dict[str, List[str]]:
        """
        Blast Radius Detection via Breadth-First Search (BFS).

        Given a compromised node, returns all reachable nodes organised
        by hop distance. This defines the "Danger Zone" — the complete
        set of resources an attacker can laterally reach.

        Parameters
        ----------
        start_node : str
            The ID of the compromised node.
        max_hops : int
            Maximum traversal depth (default: 3).

        Returns
        -------
        dict mapping hop_number -> list of reachable node IDs at that hop.
        The flat union of all values gives the full blast radius.
        """
        if start_node not in self.graph:
            return {}

        visited: Set[str] = {start_node}
        layers: Dict[str, List[str]] = {}
        current_layer: List[str] = [start_node]

        for hop in range(1, max_hops + 1):
            next_layer: List[str] = []
            for node in current_layer:
                for neighbor in self.graph.successors(node):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_layer.append(neighbor)
            if not next_layer:
                break
            layers[f"hop_{hop}"] = next_layer
            current_layer = next_layer

        return layers

    def blast_radius_flat(self, start_node: str, max_hops: int = 3) -> List[str]:
        """Returns the flat list of all nodes reachable within max_hops."""
        layers = self.blast_radius_bfs(start_node, max_hops)
        return [node for nodes in layers.values() for node in nodes]

    # ==================================================================
    # Algorithm 2 — Shortest Attack Path (Dijkstra)
    # ==================================================================

    def shortest_path_dijkstra(self, source: str, target: str) -> Tuple[List[str], float]:
        """
        Shortest Path to Crown Jewels via Dijkstra's Algorithm.

        Finds the attack path of *least resistance* from a public entry
        point to a crown jewel. Edge weights represent the exploitability
        cost of traversing each relationship.

        Parameters
        ----------
        source : str
            Public-facing entry point node ID.
        target : str
            Crown jewel / sensitive target node ID.

        Returns
        -------
        (path, total_risk_score) where path is an ordered list of node IDs.
        Returns ([], 0.0) if no path exists.
        """
        if source not in self.graph:
            return [], 0.0
        if target not in self.graph:
            return [], 0.0
        try:
            path = nx.dijkstra_path(self.graph, source, target, weight="weight")
            # Total risk = sum of node risk_scores along path + sum of edge weights
            node_risk = sum(self.graph.nodes[n].get("risk_score", 0.0) for n in path)
            edge_cost = nx.path_weight(self.graph, path, weight="weight")
            total = round(node_risk + edge_cost, 2)
            return path, total
        except (nx.NetworkXNoPath, nx.NodeNotFound, nx.NetworkXException):
            return [], 0.0

    def all_attack_paths(self, source: str, target: str,
                         cutoff: int = 10) -> List[Tuple[List[str], float]]:
        """
        Enumerates all simple paths from source to target, with their risk scores.
        Sorted by total risk score ascending (lowest cost = most dangerous).

        Parameters
        ----------
        cutoff : int
            Maximum path length to consider (prevents combinatorial explosion).
        """
        if source not in self.graph or target not in self.graph:
            return []
        try:
            paths_with_scores = []
            for path in nx.all_simple_paths(self.graph, source, target, cutoff=cutoff):
                node_risk = sum(self.graph.nodes[n].get("risk_score", 0.0) for n in path)
                edge_cost = nx.path_weight(self.graph, path, weight="weight")
                paths_with_scores.append((path, round(node_risk + edge_cost, 2)))
            paths_with_scores.sort(key=lambda x: x[1])
            return paths_with_scores
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    # ==================================================================
    # Algorithm 3 — Circular Permission Detection (DFS)
    # ==================================================================

    def detect_circular_permissions_dfs(self) -> List[List[str]]:
        """
        Detects all permission cycles using Depth-First Search.

        A cycle indicates a mutual privilege escalation loop, e.g.:
            ServiceAccount-A -> Role-B -> ServiceAccount-A

        These loops amplify blast radius: compromising any node in the
        cycle grants access to all others in the loop.

        Returns
        -------
        List of cycles; each cycle is a list of node IDs forming the loop.
        """
        try:
            return list(nx.simple_cycles(self.graph))
        except nx.NetworkXException:
            return []

    # ==================================================================
    # Task 4 — Critical Node Identification
    # ==================================================================

    def get_critical_node(self, source: str, target: str,
                          cutoff: int = 10) -> Tuple[Optional[str], int, int]:
        """
        Identifies the single node whose removal breaks the most attack paths.

        Method:
        1. Count all simple paths from source to target.
        2. For each candidate node (appearing in at least one path),
           create a read-only subgraph view excluding that node.
        3. Recount paths in the subgraph.
        4. The node causing the greatest reduction is the Critical Node.

        This is a read-only operation — the graph is never mutated.

        Parameters
        ----------
        source, target : str
            Source and target node IDs.
        cutoff : int
            Max path depth for enumeration.

        Returns
        -------
        (critical_node_id, total_paths, paths_broken)
        """
        if source not in self.graph or target not in self.graph:
            return None, 0, 0

        try:
            original_paths = list(
                nx.all_simple_paths(self.graph, source, target, cutoff=cutoff)
            )
            original_count = len(original_paths)
            if original_count == 0:
                return None, 0, 0

            # Only examine intermediate nodes (not source/target themselves)
            candidates: Set[str] = {
                node
                for path in original_paths
                for node in path
                if node not in (source, target)
            }

            critical_node: Optional[str] = None
            max_broken = 0

            for candidate in candidates:
                nodes_to_keep = [n for n in self.graph.nodes() if n != candidate]
                sub = self.graph.subgraph(nodes_to_keep)
                try:
                    new_count = sum(
                        1 for _ in nx.all_simple_paths(sub, source, target, cutoff=cutoff)
                    )
                except (nx.NodeNotFound, nx.NetworkXException):
                    new_count = 0

                broken = original_count - new_count
                if broken > max_broken:
                    max_broken = broken
                    critical_node = candidate

            return critical_node, original_count, max_broken

        except (nx.NodeNotFound, nx.NetworkXException):
            return None, 0, 0

    # ==================================================================
    # Advanced Analytics — Betweenness Centrality
    # ==================================================================

    def betweenness_centrality(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Computes betweenness centrality for all nodes in the graph.

        Nodes with high betweenness centrality are critical chokepoints
        that appear in many shortest paths. They are high-value targets
        for both attackers (as pivot points) and defenders (as hardening priorities).

        Returns the top_n nodes sorted by centrality descending.
        """
        centrality = nx.betweenness_centrality(self.graph, weight="weight")
        ranked = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_n]

    # ==================================================================
    # Advanced Analytics — PageRank Importance
    # ==================================================================

    def pagerank_importance(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Computes PageRank for all nodes, treating the graph as a trust network.

        Nodes with high PageRank are implicitly trusted by many other nodes
        (i.e., many incoming edges). These nodes are the most valuable
        targets for an attacker because compromising them yields the
        widest access.

        Returns the top_n nodes sorted by PageRank descending.
        """
        try:
            # Try scipy-accelerated PageRank first
            pr = nx.pagerank(self.graph, weight="weight")
            ranked = sorted(pr.items(), key=lambda x: x[1], reverse=True)
            return ranked[:top_n]
        except (nx.NetworkXException, ImportError, Exception):
            # Fallback: compute manually via in-degree based importance
            try:
                in_deg = dict(self.graph.in_degree(weight="weight"))
                total = sum(in_deg.values()) or 1
                importance = {n: round(d / total, 6) for n, d in in_deg.items()}
                ranked = sorted(importance.items(), key=lambda x: x[1], reverse=True)
                return ranked[:top_n]
            except Exception:
                return []

    # ==================================================================
    # Advanced Analytics — Multi-Target Attack Surface Scan
    # ==================================================================

    def scan_all_crown_jewels(
        self,
        sources: List[str],
        targets: List[str],
        cutoff: int = 10,
    ) -> List[Dict]:
        """
        Scans all source->target combinations to produce a complete
        attack surface matrix.

        Returns a list of dicts with source, target, shortest_path, risk,
        all_paths_count, severity, and critical_node info.
        """
        results = []
        for source in sources:
            for target in targets:
                if source == target:
                    continue
                path, risk = self.shortest_path_dijkstra(source, target)
                if not path:
                    continue
                all_paths = self.all_attack_paths(source, target, cutoff=cutoff)
                cn, tp, bp = self.get_critical_node(source, target, cutoff=cutoff)
                results.append({
                    "source": source,
                    "target": target,
                    "shortest_path": path,
                    "risk_score": risk,
                    "severity": self.risk_rating(risk),
                    "hops": len(path) - 1,
                    "total_paths": len(all_paths),
                    "critical_node": cn,
                    "paths_broken_by_critical": bp,
                })
        # Sort by risk descending — worst paths first
        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    # ==================================================================
    # Advanced Analytics — Risk Severity Matrix
    # ==================================================================

    def risk_severity_matrix(self) -> Dict[str, int]:
        """
        Computes a severity distribution of all nodes in the graph.

        Returns a dict: {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N, "INFORMATIONAL": N}
        """
        matrix = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for _, data in self.graph.nodes(data=True):
            score = data.get("risk_score", 0.0)
            severity = self.risk_rating(score)
            matrix[severity] += 1
        return matrix

    # ==================================================================
    # Advanced Analytics — Namespace Isolation Audit
    # ==================================================================

    def namespace_isolation_audit(self) -> Dict[str, List[Dict]]:
        """
        Detects cross-namespace trust relationships that enable lateral
        movement between namespaces. Each cross-namespace edge is a
        potential segmentation violation.

        Returns a dict:
          - "violations": list of {source, target, source_ns, target_ns, relationship}
          - "namespaces": dict of namespace -> list of node_ids
          - "isolated": list of namespaces with no outbound cross-ns edges
          - "exposed": list of namespaces with cross-ns outbound edges
        """
        violations = []
        ns_map: Dict[str, List[str]] = {}
        skip_ns = {"external", "cluster-wide", ""}

        for node_id, data in self.graph.nodes(data=True):
            ns = data.get("namespace", "")
            if ns and ns not in skip_ns:
                ns_map.setdefault(ns, []).append(node_id)

        for u, v, edge_data in self.graph.edges(data=True):
            u_ns = self.graph.nodes[u].get("namespace", "")
            v_ns = self.graph.nodes[v].get("namespace", "")
            if u_ns in skip_ns or v_ns in skip_ns:
                continue
            if u_ns != v_ns:
                violations.append({
                    "source": u,
                    "target": v,
                    "source_ns": u_ns,
                    "target_ns": v_ns,
                    "relationship": edge_data.get("relationship", "unknown"),
                })

        exposed_ns = set(v["source_ns"] for v in violations)
        isolated_ns = [ns for ns in ns_map if ns not in exposed_ns]

        return {
            "violations": violations,
            "namespaces": ns_map,
            "isolated": isolated_ns,
            "exposed": list(exposed_ns),
            "total_cross_ns": len(violations),
        }

    # ==================================================================
    # What-If Remediation Simulator
    # ==================================================================

    def what_if_remove(self, node_to_remove: str, sources: List[str],
                       targets: List[str], cutoff: int = 10) -> Dict:
        """
        Simulates the security impact of removing a node (permission/binding).

        Compares the attack surface before and after node removal.
        Returns a dict with before/after path counts, eliminated paths,
        and remaining paths.
        """
        # Before removal
        before_paths = []
        for s in sources:
            for t in targets:
                if s == t:
                    continue
                for path in nx.all_simple_paths(self.graph, s, t, cutoff=cutoff):
                    before_paths.append(path)

        # After removal (read-only subgraph view)
        remaining_nodes = [n for n in self.graph.nodes() if n != node_to_remove]
        sub = self.graph.subgraph(remaining_nodes)

        after_paths = []
        for s in sources:
            if s == node_to_remove:
                continue
            for t in targets:
                if t == node_to_remove or s == t:
                    continue
                try:
                    for path in nx.all_simple_paths(sub, s, t, cutoff=cutoff):
                        after_paths.append(path)
                except (nx.NodeNotFound, nx.NetworkXException):
                    pass

        eliminated = len(before_paths) - len(after_paths)
        pct = int((eliminated / len(before_paths)) * 100) if before_paths else 0

        # Which specific paths were broken?
        before_set = set(tuple(p) for p in before_paths)
        after_set = set(tuple(p) for p in after_paths)
        broken = [list(p) for p in before_set - after_set]

        node_data = self.graph.nodes.get(node_to_remove, {})

        return {
            "node_removed": node_to_remove,
            "node_type": node_data.get("type", "Unknown"),
            "node_name": node_data.get("name", node_to_remove),
            "before_paths": len(before_paths),
            "after_paths": len(after_paths),
            "eliminated": eliminated,
            "reduction_pct": pct,
            "broken_paths": broken[:5],  # show up to 5
            "remaining_paths": [list(p) for p in list(after_set)[:3]],
        }

    # ==================================================================
    # Utility
    # ==================================================================

    def risk_rating(self, score: float) -> str:
        """Converts a numeric risk score to a CVSS-like severity label."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "INFORMATIONAL"


if __name__ == "__main__":
    from ingestor import KubernetesIngestor
    from graph import ClusterGraph

    data = KubernetesIngestor(use_mock=True).load_data()
    cg = ClusterGraph(data)
    g = cg.get_graph()
    analyzer = SecurityAnalyzer(g)

    bfs = analyzer.blast_radius_bfs("dev-pod", 3)
    print("Blast Radius layers:", {k: len(v) for k, v in bfs.items()})

    path, score = analyzer.shortest_path_dijkstra("public-internet", "production-db")
    print(f"Shortest path ({score} risk): {' -> '.join(path)}")

    cycles = analyzer.detect_circular_permissions_dfs()
    print(f"Cycles detected: {len(cycles)}")

    cn, tp, bp = analyzer.get_critical_node("public-internet", "production-db")
    print(f"Critical node: {cn}  (breaks {bp}/{tp} attack paths)")

    print("\nBetweenness Centrality (top 5):")
    for node, score in analyzer.betweenness_centrality(5):
        print(f"  {node}: {score:.4f}")

    print("\nPageRank (top 5):")
    for node, score in analyzer.pagerank_importance(5):
        print(f"  {node}: {score:.4f}")

    print("\nRisk Severity Matrix:")
    for sev, count in analyzer.risk_severity_matrix().items():
        print(f"  {sev}: {count}")

    print("\nFull Attack Surface Scan:")
    sources = cg.get_source_nodes()
    targets = cg.get_crown_jewel_nodes()
    for r in analyzer.scan_all_crown_jewels(sources, targets):
        print(f"  {r['source']} -> {r['target']}: {r['risk_score']} ({r['severity']}) via {r['hops']} hops")

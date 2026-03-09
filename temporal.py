"""
temporal.py — Temporal Snapshot Analysis (Bonus 3)
===================================================
Saves graph snapshots over time and diffs consecutive scans to detect
newly introduced (or removed) attack paths.

Usage:
  Save a snapshot:   python main.py --mock --snapshot
  Diff two scans:    python main.py --mock --diff snapshots/snap_20260309_210000.json
"""

import datetime
import json
import os
from typing import Any, Dict, List, Tuple

import networkx as nx

from analyzer import SecurityAnalyzer


SNAPSHOT_DIR = "snapshots"


class TemporalAnalyzer:
    """
    Manages graph snapshots for temporal comparison of cluster security posture.
    """

    def __init__(self, graph: nx.DiGraph, analyzer: SecurityAnalyzer):
        self.graph = graph
        self.analyzer = analyzer

    # ------------------------------------------------------------------
    # Snapshot Save
    # ------------------------------------------------------------------

    def save_snapshot(self, source: str, target: str, cutoff: int = 10) -> str:
        """
        Saves the current graph state and all attack paths as a JSON snapshot.
        Returns the filepath of the saved snapshot.
        """
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(SNAPSHOT_DIR, f"snap_{ts}.json")

        # Capture current state
        all_paths = self.analyzer.all_attack_paths(source, target, cutoff=cutoff)
        cycles = self.analyzer.detect_circular_permissions_dfs()
        cn, tp, bp = self.analyzer.get_critical_node(source, target, cutoff=cutoff)

        snapshot: Dict[str, Any] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "source": source,
            "target": target,
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "nodes": list(self.graph.nodes()),
            "edges": [(u, v) for u, v in self.graph.edges()],
            "edge_data": {f"{u}->{v}": d for u, v, d in self.graph.edges(data=True)},
            "attack_paths": [
                {"path": path, "risk_score": score}
                for path, score in all_paths
            ],
            "cycles": cycles,
            "critical_node": {"id": cn, "total_paths": tp, "broken": bp},
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)

        return filename

    # ------------------------------------------------------------------
    # Snapshot Diff
    # ------------------------------------------------------------------

    def diff_snapshot(self, previous_file: str, source: str, target: str,
                      cutoff: int = 10) -> Dict[str, Any]:
        """
        Compares the current graph state against a previous snapshot.

        Returns a dict describing:
          - new_nodes / removed_nodes
          - new_edges / removed_edges
          - new_attack_paths / removed_attack_paths
          - new_cycles / removed_cycles
          - risk_delta
        """
        with open(previous_file, "r", encoding="utf-8") as f:
            prev = json.load(f)

        # Current state
        cur_nodes = set(self.graph.nodes())
        cur_edges = set((u, v) for u, v in self.graph.edges())
        cur_paths = self.analyzer.all_attack_paths(source, target, cutoff=cutoff)
        cur_cycles = self.analyzer.detect_circular_permissions_dfs()

        # Previous state
        prev_nodes = set(prev.get("nodes", []))
        prev_edges = set(tuple(e) for e in prev.get("edges", []))
        prev_paths_raw = prev.get("attack_paths", [])
        prev_paths = [tuple(p["path"]) for p in prev_paths_raw]
        prev_cycles = [tuple(c) for c in prev.get("cycles", [])]

        cur_path_tuples = [tuple(p) for p, _ in cur_paths]
        cur_cycle_tuples = [tuple(c) for c in cur_cycles]

        # Compute diffs
        new_nodes = cur_nodes - prev_nodes
        removed_nodes = prev_nodes - cur_nodes
        new_edges = cur_edges - prev_edges
        removed_edges = prev_edges - cur_edges

        new_attack_paths = [
            {"path": list(p), "risk_score": s}
            for p, s in cur_paths
            if tuple(p) not in set(prev_paths)
        ]
        removed_attack_paths = [
            p_raw for p_raw in prev_paths_raw
            if tuple(p_raw["path"]) not in set(cur_path_tuples)
        ]

        new_cycles = [list(c) for c in cur_cycle_tuples if c not in set(prev_cycles)]
        removed_cycles = [list(c) for c in prev_cycles if c not in set(cur_cycle_tuples)]

        # Risk delta
        prev_max_risk = max((p.get("risk_score", 0) for p in prev_paths_raw), default=0)
        cur_max_risk = max((s for _, s in cur_paths), default=0)

        diff_result = {
            "previous_snapshot": previous_file,
            "previous_timestamp": prev.get("timestamp", "unknown"),
            "current_timestamp": datetime.datetime.now().isoformat(),
            "new_nodes": list(new_nodes),
            "removed_nodes": list(removed_nodes),
            "new_edges": [list(e) for e in new_edges],
            "removed_edges": [list(e) for e in removed_edges],
            "new_attack_paths": new_attack_paths,
            "removed_attack_paths": removed_attack_paths,
            "new_cycles": new_cycles,
            "removed_cycles": removed_cycles,
            "risk_delta": round(cur_max_risk - prev_max_risk, 2),
            "summary": self._generate_diff_summary(
                new_nodes, removed_nodes, new_edges, removed_edges,
                new_attack_paths, removed_attack_paths, new_cycles, removed_cycles,
                cur_max_risk - prev_max_risk
            ),
        }

        return diff_result

    def _generate_diff_summary(
        self, new_nodes, removed_nodes, new_edges, removed_edges,
        new_paths, removed_paths, new_cycles, removed_cycles, risk_delta
    ) -> str:
        """Generates a human-readable summary of the temporal diff."""
        lines = []
        lines.append("=" * 65)
        lines.append("  TEMPORAL SECURITY ANALYSIS — SNAPSHOT DIFF")
        lines.append("=" * 65)
        lines.append("")

        if not any([new_nodes, removed_nodes, new_edges, removed_edges,
                     new_paths, removed_paths, new_cycles, removed_cycles]):
            lines.append("  [OK] No changes detected between snapshots.")
            return "\n".join(lines)

        # Topology changes
        if new_nodes:
            lines.append(f"  [+] New nodes added: {len(new_nodes)}")
            for n in list(new_nodes)[:5]:
                lines.append(f"      + {n}")
        if removed_nodes:
            lines.append(f"  [-] Nodes removed: {len(removed_nodes)}")
            for n in list(removed_nodes)[:5]:
                lines.append(f"      - {n}")
        if new_edges:
            lines.append(f"  [+] New edges added: {len(new_edges)}")
        if removed_edges:
            lines.append(f"  [-] Edges removed: {len(removed_edges)}")

        lines.append("")

        # Attack path changes — CRITICAL ALERT
        if new_paths:
            lines.append(f"  [!!] NEW ATTACK PATHS INTRODUCED: {len(new_paths)}")
            for p in new_paths[:3]:
                path_str = " -> ".join(p["path"])
                lines.append(f"      Risk: {p['risk_score']:.1f}  {path_str}")
        if removed_paths:
            lines.append(f"  [OK] Attack paths eliminated: {len(removed_paths)}")

        if new_cycles:
            lines.append(f"  [!!] NEW CIRCULAR PERMISSIONS: {len(new_cycles)}")
        if removed_cycles:
            lines.append(f"  [OK] Circular permissions removed: {len(removed_cycles)}")

        lines.append("")
        direction = "INCREASED" if risk_delta > 0 else "DECREASED" if risk_delta < 0 else "UNCHANGED"
        lines.append(f"  Risk Delta: {risk_delta:+.1f} ({direction})")
        lines.append("")
        lines.append("=" * 65)

        return "\n".join(lines)

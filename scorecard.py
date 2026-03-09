"""
scorecard.py — Cluster Security Scorecard
===========================================
Aggregates all findings into a single 0-100 security score with a
letter grade, like a credit score for your cluster's security posture.

Scoring Categories:
  - Attack paths discovered (30 points)
  - CVE exposure (20 points)
  - Privilege escalation loops (15 points)
  - Namespace isolation violations (15 points)
  - Defense depth (10 points)
  - Critical node exposure (10 points)
"""

from typing import Dict, List, Tuple

import networkx as nx

from analyzer import SecurityAnalyzer


class SecurityScorecard:
    """
    Computes a comprehensive security score (0-100) for the cluster.
    100 = perfect security posture, 0 = catastrophically insecure.
    """

    def __init__(self, graph: nx.DiGraph, analyzer: SecurityAnalyzer):
        self.graph = graph
        self.analyzer = analyzer

    def compute(self, sources: List[str], targets: List[str]) -> Dict:
        """
        Computes the full scorecard.
        Returns a dict with overall score, grade, and category breakdowns.
        """
        categories = {}

        # 1. Attack Path Score (30 pts) — fewer paths = better
        cat_attack = self._score_attack_paths(sources, targets)
        categories["attack_paths"] = cat_attack

        # 2. CVE Exposure Score (20 pts) — fewer/lower CVEs = better
        cat_cve = self._score_cve_exposure()
        categories["cve_exposure"] = cat_cve

        # 3. Privilege Escalation Loops (15 pts)
        cat_cycles = self._score_cycles()
        categories["privilege_loops"] = cat_cycles

        # 4. Namespace Isolation (15 pts)
        cat_ns = self._score_namespace_isolation()
        categories["namespace_isolation"] = cat_ns

        # 5. Defense Depth (10 pts)
        cat_depth = self._score_defense_depth(sources, targets)
        categories["defense_depth"] = cat_depth

        # 6. Critical Node Exposure (10 pts)
        cat_critical = self._score_critical_exposure(sources, targets)
        categories["critical_exposure"] = cat_critical

        total = sum(c["score"] for c in categories.values())
        total = max(0, min(100, total))  # clamp

        grade = self._grade(total)

        return {
            "overall_score": round(total, 1),
            "grade": grade,
            "categories": categories,
            "recommendation_priority": self._priority_order(categories),
        }

    # ------------------------------------------------------------------
    # Category Scorers
    # ------------------------------------------------------------------

    def _score_attack_paths(self, sources, targets) -> Dict:
        """30 points max. Deduct for each attack path found."""
        max_pts = 30
        total_paths = 0
        for s in sources:
            for t in targets:
                if s == t:
                    continue
                paths = self.analyzer.all_attack_paths(s, t, cutoff=8)
                total_paths += len(paths)

        if total_paths == 0:
            score = max_pts
            finding = "No attack paths discovered — excellent segmentation."
        elif total_paths <= 2:
            score = max_pts * 0.7
            finding = f"{total_paths} attack path(s) found — moderate risk."
        elif total_paths <= 5:
            score = max_pts * 0.4
            finding = f"{total_paths} attack paths found — significant exposure."
        else:
            score = max(0, max_pts * 0.1)
            finding = f"{total_paths} attack paths found — critical exposure."

        return {"score": round(score, 1), "max": max_pts, "finding": finding,
                "detail": f"{total_paths} total attack paths across all entry-crown pairs"}

    def _score_cve_exposure(self) -> Dict:
        """20 points max. Deduct for CVEs, especially high-severity ones."""
        max_pts = 20
        cves = []
        for _, data in self.graph.nodes(data=True):
            if data.get("cve"):
                cves.append({
                    "cve": data["cve"],
                    "cvss": data.get("risk_score", 0.0),
                    "node": data.get("name", "unknown")
                })

        if not cves:
            return {"score": max_pts, "max": max_pts,
                    "finding": "No known CVEs detected.",
                    "detail": "0 CVEs", "cves": []}

        critical_count = sum(1 for c in cves if c["cvss"] >= 9.0)
        high_count = sum(1 for c in cves if 7.0 <= c["cvss"] < 9.0)
        penalty = critical_count * 5 + high_count * 2.5 + (len(cves) - critical_count - high_count) * 1
        score = max(0, max_pts - penalty)

        return {"score": round(score, 1), "max": max_pts,
                "finding": f"{len(cves)} CVEs detected ({critical_count} critical, {high_count} high).",
                "detail": f"Total CVSS impact: {sum(c['cvss'] for c in cves):.1f}",
                "cves": cves}

    def _score_cycles(self) -> Dict:
        """15 points max. Each cycle is a severe penalty."""
        max_pts = 15
        cycles = self.analyzer.detect_circular_permissions_dfs()
        if not cycles:
            return {"score": max_pts, "max": max_pts,
                    "finding": "No privilege escalation loops detected.",
                    "detail": "0 cycles"}

        penalty = len(cycles) * 7.5
        score = max(0, max_pts - penalty)
        return {"score": round(score, 1), "max": max_pts,
                "finding": f"{len(cycles)} circular permission loop(s) detected — privilege amplification risk.",
                "detail": f"{len(cycles)} cycle(s): {', '.join(' -> '.join(c) for c in cycles[:2])}"}

    def _score_namespace_isolation(self) -> Dict:
        """15 points max. Cross-namespace edges without network policies are penalised."""
        max_pts = 15
        cross_ns_edges = 0
        for u, v in self.graph.edges():
            u_ns = self.graph.nodes[u].get("namespace", "")
            v_ns = self.graph.nodes[v].get("namespace", "")
            if u_ns and v_ns and u_ns != v_ns and u_ns not in ("external", "cluster-wide") and v_ns not in ("external", "cluster-wide"):
                cross_ns_edges += 1

        if cross_ns_edges == 0:
            return {"score": max_pts, "max": max_pts,
                    "finding": "Strong namespace isolation — no cross-namespace trust paths.",
                    "detail": "0 cross-namespace edges"}

        penalty = min(cross_ns_edges * 1.5, max_pts)
        score = max(0, max_pts - penalty)
        return {"score": round(score, 1), "max": max_pts,
                "finding": f"{cross_ns_edges} cross-namespace trust relationship(s) — lateral movement risk.",
                "detail": f"{cross_ns_edges} edges cross namespace boundaries"}

    def _score_defense_depth(self, sources, targets) -> Dict:
        """10 points max. Paths with few security barriers are penalised."""
        max_pts = 10
        min_depth = float("inf")
        for s in sources[:2]:
            for t in targets[:3]:
                if s == t:
                    continue
                path, _ = self.analyzer.shortest_path_dijkstra(s, t)
                if path:
                    depth = self._count_barriers(path)
                    min_depth = min(min_depth, depth)

        if min_depth == float("inf"):
            return {"score": max_pts, "max": max_pts,
                    "finding": "No reachable crown jewels — no depth concern.",
                    "detail": "N/A"}

        if min_depth >= 3:
            score = max_pts
            finding = f"Good defense depth — minimum {min_depth} barriers on shortest path."
        elif min_depth == 2:
            score = max_pts * 0.6
            finding = f"Moderate defense depth — only {min_depth} barriers. Consider adding segmentation."
        else:
            score = max_pts * 0.2
            finding = f"CRITICAL — only {min_depth} barrier(s) between attacker and crown jewel. Zero-trust violation."

        return {"score": round(score, 1), "max": max_pts,
                "finding": finding, "detail": f"Minimum defense depth: {min_depth}"}

    def _score_critical_exposure(self, sources, targets) -> Dict:
        """10 points max. If one node breaks >60% of paths, that's risky (single point of failure for defense)."""
        max_pts = 10
        for s in sources[:1]:
            for t in targets[:2]:
                if s == t:
                    continue
                cn, tp, bp = self.analyzer.get_critical_node(s, t)
                if cn and tp > 0:
                    pct = bp / tp
                    if pct >= 0.7:
                        # High concentration is good for defense (one node to fix)
                        return {"score": round(max_pts * 0.9, 1), "max": max_pts,
                                "finding": f"High path concentration through '{cn}' ({int(pct*100)}%). Fixing this one node drastically reduces attack surface.",
                                "detail": f"Critical node: {cn}, breaks {bp}/{tp} paths"}
                    else:
                        return {"score": round(max_pts * 0.5, 1), "max": max_pts,
                                "finding": f"Attack paths are distributed — no single chokepoint to remediate.",
                                "detail": f"Best node: {cn}, breaks {bp}/{tp} paths"}

        return {"score": max_pts, "max": max_pts,
                "finding": "No critical exposure identified.",
                "detail": "N/A"}

    def _count_barriers(self, path: List[str]) -> int:
        """Counts distinct security boundaries crossed in a path."""
        barriers = 0
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            edge_data = self.graph.edges.get((u, v), {})
            rel = edge_data.get("relationship", "")
            # These relationships represent real security barriers
            if rel in ("bound-to", "can-read", "can-exec", "authenticates-to", "mounts-hostpath"):
                barriers += 1
        return barriers

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def _grade(self, score: float) -> str:
        if score >= 90: return "A"
        if score >= 80: return "B"
        if score >= 70: return "C"
        if score >= 60: return "D"
        return "F"

    def _priority_order(self, categories: Dict) -> List[str]:
        """Returns categories sorted by urgency (lowest score% first)."""
        items = [(name, cat["score"] / cat["max"] if cat["max"] > 0 else 1.0)
                 for name, cat in categories.items()]
        items.sort(key=lambda x: x[1])
        return [name for name, _ in items]

    def format_scorecard(self, result: Dict) -> str:
        """Formats the scorecard as a CLI dashboard."""
        lines = []
        score = result["overall_score"]
        grade = result["grade"]

        # Grade color bar
        bar_filled = int(score / 2)
        bar_empty = 50 - bar_filled
        bar = "#" * bar_filled + "-" * bar_empty

        lines.append(f"  +{'=' * 62}+")
        lines.append(f"  |  CLUSTER SECURITY SCORECARD                                |")
        lines.append(f"  +{'=' * 62}+")
        lines.append(f"  |                                                              |")
        lines.append(f"  |  Overall Score:  {score:5.1f} / 100     Grade: {grade}              |")
        lines.append(f"  |  [{bar}]  |")
        lines.append(f"  |                                                              |")
        lines.append(f"  +{'-' * 62}+")
        lines.append(f"  |  {'CATEGORY':<28} {'SCORE':>6} {'MAX':>5} {'STATUS':<18} |")
        lines.append(f"  +{'-' * 62}+")

        status_labels = {
            (0.8, 1.01): "PASS",
            (0.5, 0.8):  "WARN",
            (0.0, 0.5):  "FAIL",
        }

        for name, cat in result["categories"].items():
            pct = cat["score"] / cat["max"] if cat["max"] > 0 else 0
            status = "PASS" if pct >= 0.8 else "WARN" if pct >= 0.5 else "FAIL"
            display_name = name.replace("_", " ").title()
            lines.append(f"  |  {display_name:<28} {cat['score']:>5.1f} /{cat['max']:>4}  {status:<18} |")

        lines.append(f"  +{'-' * 62}+")
        lines.append(f"  |                                                              |")
        lines.append(f"  |  Priority Remediation Order:                                 |")

        for i, priority in enumerate(result["recommendation_priority"][:3], 1):
            display = priority.replace("_", " ").title()
            cat = result["categories"][priority]
            lines.append(f"  |    {i}. {display:<25} — {cat['finding'][:30]}  |")

        lines.append(f"  |                                                              |")
        lines.append(f"  +{'=' * 62}+")

        return "\n".join(lines)

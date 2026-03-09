"""
test_algorithms.py - Unit Tests for Algorithm Correctness
===========================================================
Validates that all algorithms produce correct outputs on known small
graphs with deterministic structure. This is one of the hackathon
evaluation criteria: "BFS, Dijkstra, and DFS produce verifiably
correct outputs on test data."

Test categories:
  - BFS blast radius (6 tests)
  - Dijkstra shortest path (5 tests)
  - DFS cycle detection (4 tests)
  - Critical node identification (2 tests)
  - Risk rating utility (5 tests)
  - Betweenness centrality (2 tests)
  - Namespace isolation audit (2 tests)
  - What-if remediation (2 tests)
  - Edge cases (2 tests)

Run:  python -m pytest tests/test_algorithms.py -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import networkx as nx
import pytest
from analyzer import SecurityAnalyzer


# ====================================================================
# Fixtures
# ====================================================================

@pytest.fixture
def linear_graph():
    """A -> B -> C -> D (linear, weights 1/2/3)"""
    g = nx.DiGraph()
    g.add_node("A", type="Internet", name="A", namespace="external", risk_score=0.0)
    g.add_node("B", type="Pod", name="B", namespace="default", risk_score=5.0, cve="CVE-2024-1234")
    g.add_node("C", type="Role", name="C", namespace="default", risk_score=0.0)
    g.add_node("D", type="Database", name="D", namespace="data-tier", risk_score=10.0)
    g.add_edge("A", "B", relationship="routes-traffic-to", weight=1.0)
    g.add_edge("B", "C", relationship="uses-service-account", weight=2.0)
    g.add_edge("C", "D", relationship="can-read", weight=3.0)
    return g


@pytest.fixture
def branching_graph():
    """A->B->D (weight 2) and A->C->D (weight 6), Dijkstra must pick A->B->D"""
    g = nx.DiGraph()
    for n in ["A", "B", "C", "D"]:
        g.add_node(n, type="Pod", name=n, namespace="default", risk_score=0.0)
    g.add_edge("A", "B", relationship="r", weight=1.0)
    g.add_edge("A", "C", relationship="r", weight=5.0)
    g.add_edge("B", "D", relationship="r", weight=1.0)
    g.add_edge("C", "D", relationship="r", weight=1.0)
    return g


@pytest.fixture
def cycle_graph():
    """A->B->C->A cycle, plus A->D exit"""
    g = nx.DiGraph()
    for n in ["A", "B", "C", "D"]:
        g.add_node(n, type="ServiceAccount", name=n, namespace="default", risk_score=0.0)
    g.add_edge("A", "B", relationship="bound-to", weight=1.0)
    g.add_edge("B", "C", relationship="grants-admin-to", weight=1.0)
    g.add_edge("C", "A", relationship="grants-admin-to", weight=1.0)
    g.add_edge("A", "D", relationship="can-read", weight=1.0)
    return g


@pytest.fixture
def critical_node_graph():
    """S->X->T, S->Y->T, S->X->Y (3 paths total)"""
    g = nx.DiGraph()
    for n in ["S", "X", "Y", "T"]:
        g.add_node(n, type="Pod", name=n, namespace="default", risk_score=0.0)
    g.add_edge("S", "X", relationship="r", weight=1.0)
    g.add_edge("X", "T", relationship="r", weight=1.0)
    g.add_edge("S", "Y", relationship="r", weight=1.0)
    g.add_edge("Y", "T", relationship="r", weight=1.0)
    g.add_edge("X", "Y", relationship="r", weight=1.0)
    return g


@pytest.fixture
def cross_ns_graph():
    """Two namespaces with cross-namespace edge"""
    g = nx.DiGraph()
    g.add_node("P1", type="Pod", name="pod-1", namespace="frontend", risk_score=0.0)
    g.add_node("P2", type="Pod", name="pod-2", namespace="backend", risk_score=0.0)
    g.add_node("P3", type="Pod", name="pod-3", namespace="frontend", risk_score=0.0)
    g.add_edge("P1", "P2", relationship="routes-traffic-to", weight=1.0)
    g.add_edge("P1", "P3", relationship="can-exec", weight=1.0)
    return g


@pytest.fixture
def empty_graph():
    """An empty graph with no nodes or edges."""
    return nx.DiGraph()


@pytest.fixture
def single_node_graph():
    """A graph with a single isolated node."""
    g = nx.DiGraph()
    g.add_node("ALONE", type="Pod", name="alone", namespace="default", risk_score=5.0)
    return g


# ====================================================================
# TEST: BFS Blast Radius
# ====================================================================

class TestBlastRadiusBFS:
    def test_linear_1_hop(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        assert a.blast_radius_flat("A", 1) == ["B"]

    def test_linear_2_hops(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        assert set(a.blast_radius_flat("A", 2)) == {"B", "C"}

    def test_linear_full(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        assert set(a.blast_radius_flat("A", 3)) == {"B", "C", "D"}

    def test_nonexistent_node(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        assert a.blast_radius_flat("FAKE", 3) == []

    def test_layered_output(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        layers = a.blast_radius_bfs("A", 3)
        assert layers["hop_1"] == ["B"]
        assert layers["hop_2"] == ["C"]
        assert layers["hop_3"] == ["D"]

    def test_branching_1_hop(self, branching_graph):
        a = SecurityAnalyzer(branching_graph)
        assert set(a.blast_radius_flat("A", 1)) == {"B", "C"}


# ====================================================================
# TEST: Dijkstra
# ====================================================================

class TestDijkstra:
    def test_linear_path(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        path, risk = a.shortest_path_dijkstra("A", "D")
        assert path == ["A", "B", "C", "D"]
        assert risk == 21.0  # edges: 1+2+3=6, nodes: 0+5+0+10=15

    def test_prefers_cheaper(self, branching_graph):
        a = SecurityAnalyzer(branching_graph)
        path, _ = a.shortest_path_dijkstra("A", "D")
        assert path == ["A", "B", "D"]

    def test_no_path_reverse(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        path, risk = a.shortest_path_dijkstra("D", "A")
        assert path == []
        assert risk == 0.0

    def test_same_node(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        path, _ = a.shortest_path_dijkstra("A", "A")
        assert path == ["A"]

    def test_empty_graph(self, empty_graph):
        a = SecurityAnalyzer(empty_graph)
        path, risk = a.shortest_path_dijkstra("X", "Y")
        assert path == []
        assert risk == 0.0


# ====================================================================
# TEST: DFS Cycle Detection
# ====================================================================

class TestCycleDetection:
    def test_no_cycles_linear(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        assert len(a.detect_circular_permissions_dfs()) == 0

    def test_cycle_found(self, cycle_graph):
        a = SecurityAnalyzer(cycle_graph)
        cycles = a.detect_circular_permissions_dfs()
        assert len(cycles) == 1
        assert set(cycles[0]) == {"A", "B", "C"}

    def test_no_cycles_branching(self, branching_graph):
        a = SecurityAnalyzer(branching_graph)
        assert len(a.detect_circular_permissions_dfs()) == 0

    def test_no_cycles_empty(self, empty_graph):
        a = SecurityAnalyzer(empty_graph)
        assert len(a.detect_circular_permissions_dfs()) == 0


# ====================================================================
# TEST: Critical Node
# ====================================================================

class TestCriticalNode:
    def test_linear(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        cn, total, broken = a.get_critical_node("A", "D")
        assert cn is not None
        assert total == 1
        assert broken == 1

    def test_branching(self, critical_node_graph):
        a = SecurityAnalyzer(critical_node_graph)
        cn, total, broken = a.get_critical_node("S", "T")
        assert total == 3
        assert broken == 2
        assert cn in ("X", "Y")


# ====================================================================
# TEST: Risk Rating
# ====================================================================

class TestRiskRating:
    @pytest.mark.parametrize("score,expected", [
        (9.5, "CRITICAL"), (7.5, "HIGH"), (5.0, "MEDIUM"),
        (2.0, "LOW"), (0.0, "INFORMATIONAL"),
    ])
    def test_rating(self, score, expected):
        a = SecurityAnalyzer(nx.DiGraph())
        assert a.risk_rating(score) == expected


# ====================================================================
# TEST: Betweenness Centrality
# ====================================================================

class TestCentrality:
    def test_linear_centrality(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        top = a.betweenness_centrality(2)
        assert len(top) >= 1
        # Middle nodes B and C should have highest centrality
        top_nodes = [n for n, _ in top]
        assert "B" in top_nodes or "C" in top_nodes

    def test_empty_centrality(self, empty_graph):
        a = SecurityAnalyzer(empty_graph)
        assert a.betweenness_centrality(5) == []


# ====================================================================
# TEST: Namespace Isolation
# ====================================================================

class TestNamespaceIsolation:
    def test_cross_ns_detected(self, cross_ns_graph):
        a = SecurityAnalyzer(cross_ns_graph)
        audit = a.namespace_isolation_audit()
        assert audit["total_cross_ns"] == 1
        assert "frontend" in audit["exposed"]

    def test_same_ns_no_violation(self, linear_graph):
        """A is external, B/C are default, D is data-tier.
        B->C is same-ns, A->B has 'external' (skipped), C->D crosses ns."""
        a = SecurityAnalyzer(linear_graph)
        audit = a.namespace_isolation_audit()
        assert audit["total_cross_ns"] >= 1


# ====================================================================
# TEST: What-If Remediation
# ====================================================================

class TestWhatIf:
    def test_remove_bottleneck(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        result = a.what_if_remove("B", ["A"], ["D"])
        assert result["before_paths"] == 1
        assert result["after_paths"] == 0
        assert result["reduction_pct"] == 100

    def test_remove_nonexistent(self, linear_graph):
        a = SecurityAnalyzer(linear_graph)
        result = a.what_if_remove("FAKE", ["A"], ["D"])
        # Should not crash; paths unchanged
        assert result["before_paths"] == 1
        assert result["after_paths"] == 1


# ====================================================================
# TEST: Edge Cases
# ====================================================================

class TestEdgeCases:
    def test_single_node_blast(self, single_node_graph):
        a = SecurityAnalyzer(single_node_graph)
        assert a.blast_radius_flat("ALONE", 5) == []

    def test_single_node_dijkstra(self, single_node_graph):
        a = SecurityAnalyzer(single_node_graph)
        path, risk = a.shortest_path_dijkstra("ALONE", "ALONE")
        assert path == ["ALONE"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

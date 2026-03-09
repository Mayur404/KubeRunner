"""
reporter.py - Kill Chain Report Generator
==========================================
Generates structured Kill Chain Reports matching the hackathon sample output:
  - Warning markers, arrows, checkmarks matching exact spec format
  - MITRE ATT&CK technique mapping per hop
  - Betweenness centrality & PageRank analysis
  - Namespace isolation audit
  - Risk severity heatmap
  - Actionable remediation recommendations
  - Professional multi-page PDF report with dark cover & section styling

8 report sections + graph statistics preamble.
"""

import datetime
import re
import textwrap
from typing import Dict, List, Optional, Tuple

import networkx as nx
from colorama import Fore, Style, Back, init as colorama_init
from fpdf import FPDF

from analyzer import SecurityAnalyzer
from mitre_mapper import MITREMapper

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DIV  = "=" * 72
_THIN = "-" * 72
_W  = f"{Fore.YELLOW}{Style.BRIGHT}"      # warning colour
_OK = f"{Fore.GREEN}{Style.BRIGHT}"        # ok colour
_ER = f"{Fore.RED}{Style.BRIGHT}"          # error/critical colour
_CY = f"{Fore.CYAN}{Style.BRIGHT}"        # section colour
_RS = Style.RESET_ALL                      # reset


def _clean(text: str) -> str:
    """Strip ANSI escape codes for PDF / file output."""
    return re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])') \
             .sub('', text) \
             .encode("latin-1", errors="replace") \
             .decode("latin-1")


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class Reporter:
    """
    Generates human-readable Kill Chain Reports in CLI (coloured) and
    PDF formats.  Output format mirrors the hackathon sample output.
    """

    def __init__(self, analyzer: SecurityAnalyzer, graph: nx.DiGraph):
        self.analyzer = analyzer
        self.graph = graph
        self.mitre = MITREMapper()

    # helper
    def _lbl(self, nid: str) -> str:
        d = self.graph.nodes.get(nid, {})
        return f"{d.get('type','?')}:{d.get('name', nid)}"

    def _sev(self, s: str) -> str:
        return {
            "CRITICAL": _ER, "HIGH": _W,
            "MEDIUM": f"{Fore.CYAN}", "LOW": f"{Fore.GREEN}",
        }.get(s, "")

    # ==================================================================
    # CLI Report  (main entry)
    # ==================================================================

    def generate_cli_report(
        self, source: str, target: str,
        blast_source: str, hops: int = 3,
    ) -> str:
        L: List[str] = []
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Header
        L += [
            "", f"{_ER}{_DIV}",
            f"  KUBERNETES SECURITY  -  KILL CHAIN REPORT",
            f"  Generated: {ts}",
            f"{_DIV}{_RS}", "",
        ]

        # Graph statistics preamble
        L += self._graph_stats()

        # === Required sections ===
        L += self._sec_attack_path(source, target)
        L += self._sec_blast_radius(blast_source, hops)
        L += self._sec_cycles()
        L += self._sec_critical_node(source, target)

        # === Advanced sections ===
        L += self._sec_mitre(source, target)
        L += self._sec_analytics()
        L += self._sec_remediation(source, target)
        L += self._sec_namespace()

        L += [f"{_ER}{_DIV}", "  END OF REPORT", f"{_DIV}{_RS}", ""]
        return "\n".join(L)

    # ------------------------------------------------------------------
    # Graph Statistics Preamble
    # ------------------------------------------------------------------
    def _graph_stats(self) -> List[str]:
        n = self.graph.number_of_nodes()
        e = self.graph.number_of_edges()
        dag = nx.is_directed_acyclic_graph(self.graph)
        types = {}
        for _, d in self.graph.nodes(data=True):
            t = d.get("type", "Unknown")
            types[t] = types.get(t, 0) + 1
        type_str = ", ".join(f"{t}: {c}" for t, c in sorted(types.items()))

        L = [
            f"{_CY}[GRAPH STATISTICS]{_RS}",
            f"  Nodes: {_W}{n}{_RS}   Edges: {_W}{e}{_RS}   "
            f"DAG: {'Yes' if dag else _ER + 'No (cycles)' + _RS}",
            f"  Types: {type_str}", "", _THIN, "",
        ]
        return L

    # ------------------------------------------------------------------
    # Section 1: Attack Path  (Dijkstra)
    # ------------------------------------------------------------------
    def _sec_attack_path(self, source: str, target: str) -> List[str]:
        L = [f"{_CY}[SECTION 1] ATTACK PATH ANALYSIS  (Dijkstra's Algorithm){_RS}", _THIN]

        path, risk = self.analyzer.shortest_path_dijkstra(source, target)
        sev = self.analyzer.risk_rating(risk)

        if not path:
            L += [f"  {_OK}[OK] No attack path from '{self._lbl(source)}' to '{self._lbl(target)}'.{_RS}", ""]
            return L + [_THIN, ""]

        # ⚠ WARNING — matching hackathon sample output format
        L += [
            "",
            f"  {_ER}!!! WARNING: Attack Path Detected{_RS}",
            f"  {_W}User '{self._lbl(source)}' can reach '{self._lbl(target)}' via:{_RS}",
        ]

        # Kill chain with → arrows  (matching sample exactly)
        for i, node in enumerate(path):
            d = self.graph.nodes.get(node, {})
            name = d.get("name", node)
            cve  = d.get("cve", "")
            cvss = d.get("risk_score", 0.0)
            ns   = d.get("namespace", "")

            cve_tag = f" {_ER}(CVE {cve}, CVSS {cvss}){_RS}" if cve else ""
            prefix  = "   " if i == 0 else f"   {Fore.WHITE}-> {_RS}"
            L.append(f"  {prefix}{d.get('type','?')}:{name}{cve_tag}")

        # Summary line — matching sample format
        L += [
            "",
            f"  {Style.BRIGHT}Total Hops: {len(path)-1} | "
            f"Path Risk Score: {self._sev(sev)}{risk:.1f} ({sev}){_RS}",
        ]

        # Alternate paths
        all_paths = self.analyzer.all_attack_paths(source, target)
        if len(all_paths) > 1:
            L.append(f"  {_W}Alternate attack paths: {len(all_paths) - 1}{_RS}")
            for rank, (ap, ap_score) in enumerate(all_paths[1:3], 2):
                route = " -> ".join(self._lbl(n) for n in ap)
                L.append(f"    [Path #{rank}] Risk={ap_score:.1f}  {route}")

        L += ["", _THIN, ""]
        return L

    # ------------------------------------------------------------------
    # Section 2: Blast Radius  (BFS)
    # ------------------------------------------------------------------
    def _sec_blast_radius(self, blast_source: str, hops: int) -> List[str]:
        L = [f"{_CY}[SECTION 2] BLAST RADIUS ANALYSIS  (Breadth-First Search){_RS}", _THIN]

        layers = self.analyzer.blast_radius_bfs(blast_source, hops)
        flat = [n for nodes in layers.values() for n in nodes]

        # ✓ checkmark format from sample output
        L.append(f"  {_OK}Blast Radius of {self._lbl(blast_source)}: "
                 f"{_W}{len(flat)} resources{_RS} within {hops} hops{_RS}")
        L.append("")

        for key, nodes in layers.items():
            hop_num = key.split("_")[1]
            L.append(f"  {_CY}Hop {hop_num} ({len(nodes)} nodes):{_RS}")
            for n in nodes:
                d = self.graph.nodes.get(n, {})
                cve = d.get("cve", "")
                cve_tag = f" {_ER}[{cve}]{_RS}" if cve else ""
                L.append(f"    - {self._lbl(n)}{cve_tag}")

        if not layers:
            L.append(f"  {_OK}[OK] Node is isolated — 0 reachable resources.{_RS}")

        L += ["", _THIN, ""]
        return L

    # ------------------------------------------------------------------
    # Section 3: Cycles  (DFS)
    # ------------------------------------------------------------------
    def _sec_cycles(self) -> List[str]:
        L = [f"{_CY}[SECTION 3] CIRCULAR PERMISSION DETECTION  (Depth-First Search){_RS}", _THIN]

        cycles = self.analyzer.detect_circular_permissions_dfs()

        # ✓ checkmark format from sample output
        if cycles:
            L.append(f"  {_ER}Cycles Detected: {len(cycles)}{_RS}")
            L.append("")
            for i, cycle in enumerate(cycles, 1):
                # Show as "Service-A <-> Service-B mutual admin grant" format
                cycle_nodes = " <-> ".join(self._lbl(n) for n in cycle)
                L.append(f"  {Fore.MAGENTA}[Cycle #{i}]{_RS} {cycle_nodes}")
                L.append(f"    Impact: Mutual admin grant — privilege amplification loop")
                L.append(f"    Risk:   Compromising ANY node in this cycle grants access to ALL")
        else:
            L.append(f"  {_OK}Cycles Detected: 0{_RS}")
            L.append(f"  {_OK}[OK] No circular permission dependencies.{_RS}")

        L += ["", _THIN, ""]
        return L

    # ------------------------------------------------------------------
    # Section 4: Critical Node
    # ------------------------------------------------------------------
    def _sec_critical_node(self, source: str, target: str) -> List[str]:
        L = [f"{_CY}[SECTION 4] CRITICAL NODE IDENTIFICATION{_RS}", _THIN]

        cn, tp, bp = self.analyzer.get_critical_node(source, target)

        if cn:
            d = self.graph.nodes.get(cn, {})
            pct = int((bp / tp) * 100) if tp else 0

            # Matching sample: "Recommendation: Remove permission binding ..."
            L += [
                f"  {Fore.BLUE}{Style.BRIGHT}RECOMMENDATION:{_RS}",
                f"  Remove / restrict permission binding '{self._lbl(cn)}'",
                f"  to eliminate {_ER}{bp} of {tp}{_RS} attack paths ({pct}% reduction).",
                "",
                f"  Node ID    : {cn}",
                f"  Type       : {d.get('type', '?')}",
                f"  Namespace  : {d.get('namespace', '?')}",
            ]
            desc = d.get("description", "")
            if desc:
                L.append(f"  Rationale  : {desc}")
        else:
            L.append(f"  {_OK}[OK] No single critical node identified.{_RS}")

        L += ["", _THIN, ""]
        return L

    # ------------------------------------------------------------------
    # Section 5: MITRE ATT&CK Mapping
    # ------------------------------------------------------------------
    def _sec_mitre(self, source: str, target: str) -> List[str]:
        L = [f"{_CY}[SECTION 5] MITRE ATT&CK FOR CONTAINERS MAPPING{_RS}", _THIN]

        path, _ = self.analyzer.shortest_path_dijkstra(source, target)
        if not path:
            L += [f"  {_OK}[OK] No attack path to map.{_RS}", "", _THIN, ""]
            return L

        mappings = self.mitre.map_attack_path(self.graph, path)
        tactics = self.mitre.get_all_tactics(mappings)
        L.append(f"  Kill chain tactics: {_W}{', '.join(tactics)}{_RS}")
        L.append("")

        for m in mappings:
            L.append(f"  {_W}[Hop {m['hop']}]{_RS} "
                     f"{self._lbl(m['source'])} -> {self._lbl(m['target'])}")
            L.append(f"    Technique : {_CY}{m['mitre_id']} - {m['mitre_name']}{_RS}")
            L.append(f"    Tactic    : {m['tactic']}")
            L.append(f"    Detail    : {m['description']}")
            L.append("")

        L += [_THIN, ""]
        return L

    # ------------------------------------------------------------------
    # Section 6: Advanced Analytics
    # ------------------------------------------------------------------
    def _sec_analytics(self) -> List[str]:
        L = [f"{_CY}[SECTION 6] ADVANCED GRAPH ANALYTICS{_RS}", _THIN]

        # Risk severity matrix (histogram)
        matrix = self.analyzer.risk_severity_matrix()
        L.append(f"  {Style.BRIGHT}Risk Severity Distribution:{_RS}")
        for sev, count in matrix.items():
            bar = "#" * count
            color = self._sev(sev)
            L.append(f"    {sev:<15} {color}{bar} ({count}){_RS}")
        L.append("")

        # Betweenness Centrality
        L.append(f"  {Style.BRIGHT}Betweenness Centrality (Top Chokepoints):{_RS}")
        for node, score in self.analyzer.betweenness_centrality(5):
            lbl = self._lbl(node)
            bar = "|" * max(int(score * 100), 1)
            L.append(f"    {lbl:<40} {_W}{bar} {score:.4f}{_RS}")
        L.append("")

        # PageRank
        L.append(f"  {Style.BRIGHT}PageRank / Node Importance:{_RS}")
        for node, score in self.analyzer.pagerank_importance(5):
            lbl = self._lbl(node)
            L.append(f"    {lbl:<40} {_CY}{score:.4f}{_RS}")

        L += ["", _THIN, ""]
        return L

    # ------------------------------------------------------------------
    # Section 7: Remediation
    # ------------------------------------------------------------------
    def _sec_remediation(self, source: str, target: str) -> List[str]:
        L = [f"{_CY}[SECTION 7] REMEDIATION PLAN{_RS}", _THIN]

        path, _ = self.analyzer.shortest_path_dijkstra(source, target)
        if not path:
            L += [f"  {_OK}[OK] No remediation needed.{_RS}", "", _THIN, ""]
            return L

        mappings = self.mitre.map_attack_path(self.graph, path)
        rems = self.mitre.generate_remediation_plan(mappings)

        L.append(f"  Prioritised actions to break the kill chain:")
        L.append("")
        for i, (ctx, action) in enumerate(rems, 1):
            L.append(f"  {_OK}{i:2d}.{_RS} [{ctx}]")
            L.append(f"      -> {action}")

        L += ["", _THIN, ""]
        return L

    # ------------------------------------------------------------------
    # Section 8: Namespace Isolation
    # ------------------------------------------------------------------
    def _sec_namespace(self) -> List[str]:
        L = [f"{_CY}[SECTION 8] NAMESPACE ISOLATION AUDIT{_RS}", _THIN]

        audit = self.analyzer.namespace_isolation_audit()
        violations = audit["violations"]
        L.append(f"  Namespaces  : {len(audit['namespaces'])}")
        L.append(f"  Isolated    : {_OK}{len(audit['isolated'])}{_RS}")
        L.append(f"  Exposed     : {_ER}{len(audit['exposed'])}{_RS}")
        L.append(f"  Violations  : {_W}{audit['total_cross_ns']}{_RS}")
        L.append("")

        if violations:
            for i, v in enumerate(violations[:8], 1):
                L.append(f"  [{i}] {v['source_ns']} -> {v['target_ns']}:  "
                         f"{self._lbl(v['source'])} --[{v['relationship']}]--> "
                         f"{self._lbl(v['target'])}")
        else:
            L.append(f"  {_OK}[OK] Strong namespace isolation.{_RS}")

        L += ["", _THIN, ""]
        return L

    # ==================================================================
    # PDF Report
    # ==================================================================

    def generate_pdf_report(
        self, report_text: str,
        output_file: str = "Kill_Chain_Report.pdf",
    ) -> None:
        """Render the Kill Chain Report as a professional multi-page PDF."""
        plain = _clean(report_text)
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        # ── COVER PAGE ──
        pdf.add_page()
        pdf.set_fill_color(15, 23, 42)
        pdf.rect(0, 0, 210, 297, "F")

        pdf.set_y(60)
        pdf.set_font("Helvetica", "B", 28)
        pdf.set_text_color(239, 68, 68)
        pdf.cell(0, 14, "KUBERNETES ATTACK PATH", align="C", ln=True)
        pdf.cell(0, 14, "VISUALIZER", align="C", ln=True)

        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(248, 250, 252)
        pdf.cell(0, 10, "Kill Chain Security Report", align="C", ln=True)
        pdf.ln(6)

        ts = datetime.datetime.now().strftime("%B %d, %Y  %H:%M:%S")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(0, 8, f"Generated: {ts}", align="C", ln=True)
        pdf.cell(0, 8, "Graph-Based Security Analysis for Cloud-Native Infrastructure", align="C", ln=True)

        pdf.ln(20)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, "Algorithms: BFS | Dijkstra | DFS | Critical Node | Betweenness Centrality | PageRank", align="C", ln=True)
        pdf.cell(0, 6, "Framework: MITRE ATT&CK for Containers", align="C", ln=True)
        pdf.cell(0, 6, "Classification: CONFIDENTIAL", align="C", ln=True)

        # ── TABLE OF CONTENTS ──
        pdf.add_page()
        pdf.set_fill_color(255, 255, 255)
        pdf.rect(0, 0, 210, 297, "F")
        pdf.set_fill_color(15, 23, 42)
        pdf.rect(0, 0, 210, 16, "F")
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(248, 250, 252)
        pdf.set_y(4)
        pdf.cell(0, 8, "  TABLE OF CONTENTS", ln=True)
        pdf.ln(8)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(15, 23, 42)
        toc = [
            "Graph Statistics",
            "Section 1: Attack Path Analysis (Dijkstra)",
            "Section 2: Blast Radius Analysis (BFS)",
            "Section 3: Circular Permission Detection (DFS)",
            "Section 4: Critical Node Identification",
            "Section 5: MITRE ATT&CK Mapping",
            "Section 6: Advanced Graph Analytics",
            "Section 7: Remediation Plan",
            "Section 8: Namespace Isolation Audit",
        ]
        for i, title in enumerate(toc):
            pdf.cell(0, 8, f"  {i}. {title}", ln=True)

        pdf.ln(10)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, "  Appendices: Attack Simulation, Security Scorecard (available via CLI)", ln=True)

        # ── CONTENT PAGES ──
        pdf.add_page()
        pdf.set_fill_color(255, 255, 255)
        pdf.rect(0, 0, 210, 297, "F")
        pdf.set_fill_color(15, 23, 42)
        pdf.rect(0, 0, 210, 16, "F")
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(248, 250, 252)
        pdf.set_y(4)
        pdf.cell(0, 8, "  KILL CHAIN ANALYSIS - DETAILED FINDINGS", ln=True)
        pdf.ln(4)

        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(15, 23, 42)

        for raw in plain.split("\n"):
            line = raw.rstrip()

            if line.strip().startswith("[SECTION") or line.strip().startswith("[GRAPH"):
                pdf.ln(2)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(226, 232, 240)
                pdf.set_text_color(15, 23, 42)
                pdf.cell(0, 6, f"  {line.strip()}", ln=True, fill=True)
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(30, 30, 30)
                continue

            if line.strip().startswith("=") or line.strip().startswith("-"):
                pdf.set_draw_color(203, 213, 225)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(1)
                continue

            if "WARNING" in line or "[!!]" in line:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(254, 226, 226)
                pdf.set_text_color(185, 28, 28)
                pdf.cell(0, 6, f"  {line.strip()}", ln=True, fill=True)
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(30, 30, 30)
                continue

            if "[OK]" in line:
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(21, 128, 61)
                pdf.cell(0, 4, f"  {line.strip()}", ln=True)
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(30, 30, 30)
                continue

            if "RECOMMENDATION" in line:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(30, 64, 175)
                pdf.multi_cell(0, 4, f"  {line.strip()}")
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(30, 30, 30)
                continue

            if "Technique" in line and "T1" in line:
                pdf.set_font("Courier", "B", 7)
                pdf.set_text_color(6, 95, 70)
                pdf.cell(0, 4, _clean(line), ln=True)
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(30, 30, 30)
                continue

            if len(line) > 105:
                for wrapped in textwrap.wrap(line, 100):
                    pdf.cell(0, 3.5, _clean(wrapped), ln=True)
            else:
                pdf.cell(0, 3.5, _clean(line), ln=True)

        # Footer
        pdf.set_y(-20)
        pdf.set_font("Helvetica", "I", 6)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(0, 4, "K8s Attack Path Visualizer | Confidential Security Report | Do Not Distribute", align="C", ln=True)

        pdf.output(output_file)
        print(f"  {_OK}[+] PDF Kill Chain Report: {output_file}{_RS}")

"""
main.py — Kubernetes Attack Path Visualizer (Advanced)
=======================================================
CLI entry point with full feature set:

  Core:
    --mock / --live / --filepath   Data source selection
    --source / --target            Attack path endpoints
    --blast-source / --blast-hops  Blast radius configuration

  Output:
    --pdf / --no-pdf               PDF Kill Chain Report
    --export-json                  Machine-readable JSON results
    --list-nodes                   Print all nodes and exit
    --visualize                    Generate interactive HTML graph (Bonus 1)

  Advanced:
    --full-scan                    Auto-scan all entry points vs all crown jewels
    --snapshot                     Save graph snapshot for temporal analysis (Bonus 3)
    --diff PREV_SNAPSHOT           Diff current state against a previous snapshot

Run `python main.py --help` for the complete argument reference.
"""

import argparse
import json
import sys

from colorama import Fore, Style, init as colorama_init

from analyzer import SecurityAnalyzer
from graph import ClusterGraph
from ingestor import KubernetesIngestor
from reporter import Reporter

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = f"""{Fore.RED}{Style.BRIGHT}
  _  __  ___     _   _   _             _      ____       _   _
 | |/ / ( _ )   / \\ | |_| |_ __ _  ___| | __ |  _ \\ __ _| |_| |__
 | ' /  / _ \\  / _ \\| __| __/ _` |/ __| |/ / | |_) / _` | __| '_ \\
 | . \\ | (_) |/ ___ \\ |_| || (_| | (__|   <  |  __/ (_| | |_| | | |
 |_|\\_\\ \\___//_/   \\_\\__|\\__\\__,_|\\___|_|\\_\\ |_|   \\__,_|\\__|_| |_|
{Style.RESET_ALL}
{Fore.CYAN}  Kubernetes Attack Path Visualizer  v2.0{Style.RESET_ALL}
  Graph-Based Security Analysis for Cloud-Native Infrastructure
  Algorithms: BFS | Dijkstra | DFS | Centrality | PageRank
  Framework:  MITRE ATT&CK for Containers
"""


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="k8s-attack-viz",
        description="K8s Attack Path Visualizer — Advanced graph-based cluster security analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:{Style.RESET_ALL}
  Quick analysis with mock data:
    python main.py --mock

  Full scan (auto-detect all entry points & crown jewels):
    python main.py --mock --full-scan

  Generate interactive HTML graph visualization:
    python main.py --mock --visualize

  Save a temporal snapshot for future diffing:
    python main.py --mock --snapshot

  Diff against a previous snapshot:
    python main.py --mock --diff snapshots/snap_20260309.json

  Custom source/target with JSON export:
    python main.py --mock --source public-internet --target etcd-pod --export-json out.json
        """,
    )

    # Data source
    ds = p.add_mutually_exclusive_group()
    ds.add_argument("--mock", action="store_true", help="Use built-in mock dataset (default)")
    ds.add_argument("--live", action="store_true", help="Scrape live cluster via kubectl")
    p.add_argument("--filepath", type=str, default="mock-cluster-graph.json",
                   help="Path to a custom cluster graph JSON file")

    # Analysis targets
    p.add_argument("--source", type=str, default="public-internet",
                   help="Entry point node ID (default: public-internet)")
    p.add_argument("--target", type=str, default="production-db",
                   help="Crown jewel target node ID (default: production-db)")
    p.add_argument("--blast-source", type=str, default="dev-pod",
                   help="Compromised node for blast radius (default: dev-pod)")
    p.add_argument("--blast-hops", type=int, default=3, metavar="N",
                   help="Max BFS depth (default: 3)")

    # Output
    p.add_argument("--pdf", type=str, default="Kill_Chain_Report.pdf", metavar="FILE",
                   help="PDF output path (default: Kill_Chain_Report.pdf)")
    p.add_argument("--no-pdf", action="store_true", help="Skip PDF generation")
    p.add_argument("--export-json", type=str, metavar="FILE",
                   help="Export results as machine-readable JSON")
    p.add_argument("--list-nodes", action="store_true",
                   help="Print all node IDs and exit")

    # Advanced features
    p.add_argument("--visualize", action="store_true",
                   help="Generate interactive HTML graph (Bonus 1)")
    p.add_argument("--full-scan", action="store_true",
                   help="Auto-scan all entry points vs all crown jewels")
    p.add_argument("--snapshot", action="store_true",
                   help="Save graph snapshot for temporal diffing (Bonus 3)")
    p.add_argument("--diff", type=str, metavar="PREV_FILE",
                   help="Diff current state against a previous snapshot")

    # Killer features
    p.add_argument("--simulate", action="store_true",
                   help="Run attack simulation with step-by-step adversary narrative")
    p.add_argument("--scorecard", action="store_true",
                   help="Generate cluster security scorecard (0-100 grade)")
    p.add_argument("--what-if-remove", type=str, metavar="NODE_ID",
                   help="Simulate removing a node and show before/after attack surface")

    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(BANNER)
    args = build_parser().parse_args()
    use_mock = args.mock or not args.live

    # ---- 1. Ingest ----
    print(f"{Fore.CYAN}[1/4] Loading cluster state...{Style.RESET_ALL}")
    try:
        ingestor = KubernetesIngestor(use_mock=use_mock, mock_file_path=args.filepath)
        raw_data = ingestor.load_data()
    except FileNotFoundError as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    # ---- 2. Graph ----
    print(f"{Fore.CYAN}[2/4] Building DAG...{Style.RESET_ALL}")
    cg = ClusterGraph(raw_data)
    g = cg.get_graph()
    s = cg.summary()

    print(f"      Cluster     : {s['cluster_name']}")
    print(f"      Nodes       : {Fore.YELLOW}{s['nodes']}{Style.RESET_ALL}")
    print(f"      Edges       : {Fore.YELLOW}{s['edges']}{Style.RESET_ALL}")
    print(f"      Is DAG      : {'Yes' if s['is_dag'] else Fore.RED + 'No (cycles present)' + Style.RESET_ALL}")
    print(f"      Crown Jewels: {Fore.RED}{', '.join(s['crown_jewels']) or 'None'}{Style.RESET_ALL}")
    print(f"      Entry Points: {Fore.GREEN}{', '.join(s['source_nodes']) or 'None'}{Style.RESET_ALL}")

    # ---- List nodes ----
    if args.list_nodes:
        print(f"\n{Fore.CYAN}[NODE LIST]{Style.RESET_ALL}")
        print(f"  {'ID':<35} {'TYPE':<18} {'NAMESPACE':<18} {'RISK':>6} {'CVE'}")
        print("-" * 95)
        for nid, data in sorted(g.nodes(data=True), key=lambda x: x[1].get("type", "")):
            risk = data.get("risk_score", 0.0)
            cve = data.get("cve", "")
            rc = Fore.RED if risk >= 7 else Fore.YELLOW if risk >= 4 else ""
            print(f"  {nid:<35} {data.get('type',''):<18} {data.get('namespace',''):<18} {rc}{risk:>6.1f}{Style.RESET_ALL} {cve}")
        sys.exit(0)

    # Validate nodes
    for label, nid in [("--source", args.source), ("--target", args.target), ("--blast-source", args.blast_source)]:
        if nid not in g:
            print(f"{Fore.RED}[ERROR] Node '{nid}' (from {label}) not found. Use --list-nodes.{Style.RESET_ALL}")
            sys.exit(1)

    # ---- 3. Analyze ----
    print(f"{Fore.CYAN}[3/4] Running security algorithms...{Style.RESET_ALL}")
    analyzer = SecurityAnalyzer(g)
    reporter = Reporter(analyzer, g)

    # ---- 4. Report ----
    print(f"{Fore.CYAN}[4/4] Generating Kill Chain Report...{Style.RESET_ALL}")
    report = reporter.generate_cli_report(
        source=args.source, target=args.target,
        blast_source=args.blast_source, hops=args.blast_hops,
    )
    print(report)

    # PDF
    if not args.no_pdf:
        reporter.generate_pdf_report(report, output_file=args.pdf)

    # JSON export
    if args.export_json:
        _export_json(analyzer, cg, args)

    # ---- Full Scan ----
    if args.full_scan:
        _full_scan(analyzer, cg)

    # ---- Attack Simulation ----
    if args.simulate:
        _simulate(g, analyzer, args)

    # ---- Security Scorecard ----
    if args.scorecard:
        _scorecard(g, analyzer, cg)

    # ---- What-If Remediation ----
    if getattr(args, 'what_if_remove', None):
        _what_if(analyzer, cg, args)

    # ---- Visualization (Bonus 1) ----
    if args.visualize:
        _visualize(g, analyzer, args)

    # ---- Temporal (Bonus 3) ----
    if args.snapshot:
        _snapshot(g, analyzer, args)
    if args.diff:
        _diff(g, analyzer, args)


# ---------------------------------------------------------------------------
# Feature Functions
# ---------------------------------------------------------------------------

def _export_json(analyzer, cg, args):
    path, risk = analyzer.shortest_path_dijkstra(args.source, args.target)
    blast = analyzer.blast_radius_flat(args.blast_source, args.blast_hops)
    cycles = analyzer.detect_circular_permissions_dfs()
    cn, tp, bp = analyzer.get_critical_node(args.source, args.target)
    all_paths = analyzer.all_attack_paths(args.source, args.target)
    centrality = analyzer.betweenness_centrality(10)
    pagerank = analyzer.pagerank_importance(10)
    matrix = analyzer.risk_severity_matrix()

    output = {
        "shortest_attack_path": {"nodes": path, "risk_score": risk,
                                  "severity": analyzer.risk_rating(risk)},
        "all_attack_paths": [{"nodes": p, "risk_score": s} for p, s in all_paths],
        "blast_radius": {"source": args.blast_source, "max_hops": args.blast_hops,
                          "reachable": blast, "count": len(blast)},
        "cycles": cycles,
        "critical_node": {"id": cn, "total_paths": tp, "paths_broken": bp},
        "betweenness_centrality": {n: round(s, 4) for n, s in centrality},
        "pagerank": {n: round(s, 4) for n, s in pagerank},
        "risk_matrix": matrix,
    }
    with open(args.export_json, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"  {Fore.GREEN}[+] JSON exported: {args.export_json}{Style.RESET_ALL}")


def _full_scan(analyzer, cg):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[FULL ATTACK SURFACE SCAN]{Style.RESET_ALL}")
    sources = cg.get_source_nodes()
    targets = cg.get_crown_jewel_nodes()
    if not sources or not targets:
        print(f"  {Fore.YELLOW}No source/target nodes detected for full scan.{Style.RESET_ALL}")
        return
    results = analyzer.scan_all_crown_jewels(sources, targets)
    print(f"  {'SOURCE':<25} {'TARGET':<25} {'RISK':>6} {'SEV':<10} {'HOPS':>4} {'PATHS':>5} {'CRITICAL NODE'}")
    print("-" * 110)
    for r in results:
        sc = Fore.RED if r["severity"] == "CRITICAL" else Fore.YELLOW if r["severity"] == "HIGH" else ""
        print(f"  {r['source']:<25} {r['target']:<25} {sc}{r['risk_score']:>6.1f}{Style.RESET_ALL} "
              f"{r['severity']:<10} {r['hops']:>4} {r['total_paths']:>5} {r.get('critical_node','N/A')}")
    print()


def _visualize(g, analyzer, args):
    from visualizer import generate_visualization
    out = generate_visualization(
        g, analyzer, args.source, args.target,
        args.blast_source, args.blast_hops, "attack_graph.html",
    )
    print(f"  {Fore.GREEN}[+] Interactive visualization: {out}{Style.RESET_ALL}")
    print(f"      Open in your browser to explore the attack graph.")


def _snapshot(g, analyzer, args):
    from temporal import TemporalAnalyzer
    ta = TemporalAnalyzer(g, analyzer)
    path = ta.save_snapshot(args.source, args.target)
    print(f"  {Fore.GREEN}[+] Snapshot saved: {path}{Style.RESET_ALL}")


def _diff(g, analyzer, args):
    from temporal import TemporalAnalyzer
    ta = TemporalAnalyzer(g, analyzer)
    diff = ta.diff_snapshot(args.diff, args.source, args.target)
    print(diff["summary"])


def _simulate(g, analyzer, args):
    from simulator import AttackSimulator
    sim = AttackSimulator(g, analyzer)
    result = sim.simulate_attack(args.source, args.target)
    report = sim.format_simulation_report(result)
    print(f"\n{Fore.RED}{Style.BRIGHT}[ATTACK SIMULATION]{Style.RESET_ALL}")
    print(report)


def _scorecard(g, analyzer, cg):
    from scorecard import SecurityScorecard
    sc = SecurityScorecard(g, analyzer)
    sources = cg.get_source_nodes()
    targets = cg.get_crown_jewel_nodes()
    result = sc.compute(sources, targets)
    dashboard = sc.format_scorecard(result)
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[SECURITY SCORECARD]{Style.RESET_ALL}")
    print(dashboard)

    # Print detailed category findings
    print(f"\n  {Style.BRIGHT}Category Details:{Style.RESET_ALL}")
    for name, cat in result["categories"].items():
        display = name.replace('_', ' ').title()
        pct = cat['score'] / cat['max'] * 100 if cat['max'] else 0
        color = Fore.GREEN if pct >= 80 else Fore.YELLOW if pct >= 50 else Fore.RED
        print(f"  {color}[{cat['score']:>5.1f}/{cat['max']:>3}]{Style.RESET_ALL} {display}")
        print(f"          {cat['finding']}")
    print()


def _what_if(analyzer, cg, args):
    node_id = args.what_if_remove
    sources = cg.get_source_nodes()
    targets = cg.get_crown_jewel_nodes()
    result = analyzer.what_if_remove(node_id, sources, targets)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}[WHAT-IF REMEDIATION SIMULATOR]{Style.RESET_ALL}")
    print(f"  Simulating removal of: {Fore.YELLOW}{result['node_type']}:{result['node_name']}{Style.RESET_ALL} ({node_id})")
    print(f"")
    print(f"  Attack paths BEFORE: {Fore.RED}{result['before_paths']}{Style.RESET_ALL}")
    print(f"  Attack paths AFTER : {Fore.GREEN}{result['after_paths']}{Style.RESET_ALL}")
    print(f"  Paths eliminated   : {Fore.GREEN}{Style.BRIGHT}{result['eliminated']}{Style.RESET_ALL} ({result['reduction_pct']}% reduction)")
    print(f"")

    if result['broken_paths']:
        print(f"  {Style.BRIGHT}Broken attack paths:{Style.RESET_ALL}")
        for i, bp in enumerate(result['broken_paths'][:3], 1):
            route = ' -> '.join(bp)
            print(f"    {Fore.RED}[x]{Style.RESET_ALL} {route}")

    if result['remaining_paths']:
        print(f"\n  {Style.BRIGHT}Remaining attack paths (still active):{Style.RESET_ALL}")
        for i, rp in enumerate(result['remaining_paths'][:3], 1):
            route = ' -> '.join(rp)
            print(f"    {Fore.YELLOW}[!]{Style.RESET_ALL} {route}")
    print()


if __name__ == "__main__":
    main()

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
import time

from colorama import Fore, Style, init as colorama_init

from analyzer import SecurityAnalyzer
from graph import ClusterGraph
from ingestor import KubernetesIngestor
from reporter import Reporter

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# CLI Aesthetics & Logging
# ---------------------------------------------------------------------------

def log_info(msg: str):
    print(f"{Fore.BLUE}{Style.BRIGHT}[*]{Style.RESET_ALL} {msg}")

def log_success(msg: str):
    print(f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {msg}")

def log_warn(msg: str):
    print(f"{Fore.YELLOW}{Style.BRIGHT}[~]{Style.RESET_ALL} {msg}")

def log_error(msg: str):
    print(f"{Fore.RED}{Style.BRIGHT}[x]{Style.RESET_ALL} {msg}")
    
def log_step(step: str, msg: str):
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[{step}]{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}{msg}{Style.RESET_ALL}")

def log_detail(msg: str):
    print(f"    {Fore.LIGHTBLACK_EX}{msg}{Style.RESET_ALL}")


BANNER = f"""
{Fore.RED}{Style.BRIGHT}██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗ 
██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
█████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Style.RESET_ALL}

{Fore.CYAN}{Style.BRIGHT}► KubeRunner Attack Path Visualizer v2.0{Style.RESET_ALL}
{Fore.WHITE}  Graph-Based Security Analysis for Cloud-Native Infrastructure
  Algorithms: BFS | Dijkstra | DFS | PageRank | Centrality
  Framework:  MITRE ATT&CK for Containers{Style.RESET_ALL}
"""

# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kuberunner",
        description=f"{Fore.CYAN}K8s Attack Path Visualizer — Advanced graph-based cluster security analysis.{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
{Fore.MAGENTA}{Style.BRIGHT}=================[ QUICKSTART & EXAMPLES ]================={Style.RESET_ALL}

{Fore.GREEN}[1] Run Full Security Audit (Mock Data):{Style.RESET_ALL}
    $ python main.py --mock
    (Generates 8-section Kill Chain Report + saves PDF)

{Fore.GREEN}[2] See The Magic (Killer Differentiator Features):{Style.RESET_ALL}
    $ python main.py --mock --simulate --scorecard
    (Runs step-by-step adversary narrative & gives 0-100 grade)

{Fore.GREEN}[3] Visualize The Attack Graph in Browser:{Style.RESET_ALL}
    $ python main.py --mock --visualize

{Fore.GREEN}[4] What-If Remediation Simulator:{Style.RESET_ALL}
    $ python main.py --mock --what-if-remove jump-server-pod
    (Simulates deleting a node and compares Before vs After attack paths)

{Fore.GREEN}[5] Full Attack Surface Scan:{Style.RESET_ALL}
    $ python main.py --mock --full-scan
    (Automatically maps all valid Entry Point -> Crown Jewel paths)

{Fore.GREEN}[6] Continuous Posture Tracking (Temporal Diffing):{Style.RESET_ALL}
    $ python main.py --mock --snapshot
    $ python main.py --mock --diff snapshots/snap_20260310_1200.json
"""
    )

    # Data source
    g_data = p.add_argument_group(f"{Fore.YELLOW}Data Source Options{Style.RESET_ALL}")
    ds = g_data.add_mutually_exclusive_group()
    ds.add_argument("--mock", action="store_true", help="Use built-in 40-node mock dataset (default)")
    ds.add_argument("--live", action="store_true", help="Scrape live cluster via kubectl")
    g_data.add_argument("--filepath", type=str, default="mock-cluster-graph.json",
                   help="Path to a custom cluster graph JSON file")

    # Analysis targets
    g_target = p.add_argument_group(f"{Fore.YELLOW}Analysis Targets{Style.RESET_ALL}")
    g_target.add_argument("--source", type=str, default="public-internet",
                   help="Entry point node ID (default: public-internet)")
    g_target.add_argument("--target", type=str, default="production-db",
                   help="Crown jewel target node ID (default: production-db)")
    g_target.add_argument("--blast-source", type=str, default="dev-pod",
                   help="Compromised node for blast radius (default: dev-pod)")
    g_target.add_argument("--blast-hops", type=int, default=3, metavar="N",
                   help="Max BFS traversing depth (default: 3)")

    # Output
    g_out = p.add_argument_group(f"{Fore.YELLOW}Output & Reporting{Style.RESET_ALL}")
    g_out.add_argument("--pdf", type=str, default="Kill_Chain_Report.pdf", metavar="FILE",
                   help="PDF output path (default: Kill_Chain_Report.pdf)")
    g_out.add_argument("--no-pdf", action="store_true", help="Skip PDF generation (console only)")
    g_out.add_argument("--export-json", type=str, metavar="FILE",
                   help="Export full results as machine-readable JSON")
    g_out.add_argument("--list-nodes", action="store_true",
                   help="Print all cluster nodes and exit")

    # Advanced features
    g_adv = p.add_argument_group(f"{Fore.YELLOW}Advanced & Killer Features{Style.RESET_ALL}")
    g_adv.add_argument("--visualize", action="store_true",
                   help="[Bonus] Generate interactive HTML graph via Cytoscape.js")
    g_adv.add_argument("--full-scan", action="store_true",
                   help="Auto-scan all entry points vs all crown jewels")
    g_adv.add_argument("--snapshot", action="store_true",
                   help="[Bonus] Save graph snapshot for temporal diffing")
    g_adv.add_argument("--diff", type=str, metavar="PREV_FILE",
                   help="[Bonus] Diff current state against a previous snapshot")
    g_adv.add_argument("--simulate", action="store_true",
                   help="[Killer] Run attack simulation with step-by-step adversary narrative")
    g_adv.add_argument("--scorecard", action="store_true",
                   help="[Killer] Generate comprehensive cluster security scorecard (0-100 grade)")
    g_adv.add_argument("--what-if-remove", type=str, metavar="NODE_ID",
                   help="[Killer] Simulate removing a node and show before/after impact")

    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(BANNER)
    args = build_parser().parse_args()
    use_mock = args.mock or not args.live

    # ---- 1. Ingest ----
    log_step("PHASE 1", "Ingestion & Enrichment Pipeline")
    try:
        log_info(f"Targeting environment: {'Mock Dataset' if use_mock else 'Live Kubernetes Cluster'}")
        if use_mock:
            log_detail(f"Source file: {args.filepath}")
        
        t0 = time.time()
        ingestor = KubernetesIngestor(use_mock=use_mock, mock_file_path=args.filepath)
        raw_data = ingestor.load_data()
        t1 = time.time()
        
        log_success(f"Successfully ingested raw cluster state ({((t1-t0)*1000):.1f}ms)")
    except FileNotFoundError as e:
        log_error(str(e))
        sys.exit(1)

    # ---- 2. Graph ----
    log_step("PHASE 2", "Graph Construction & Analysis Initialization")
    
    t0 = time.time()
    cg = ClusterGraph(raw_data)
    g = cg.get_graph()
    s = cg.summary()
    t1 = time.time()

    log_success(f"Built NetworkX DiGraph successfully ({((t1-t0)*1000):.1f}ms)")
    log_info(f"Context: {Fore.YELLOW}{s['cluster_name']}{Style.RESET_ALL}")
    log_info(f"Nodes  : {Fore.WHITE}{Style.BRIGHT}{s['nodes']}{Style.RESET_ALL} entities mapped")
    log_info(f"Edges  : {Fore.WHITE}{Style.BRIGHT}{s['edges']}{Style.RESET_ALL} trust relationships established")
    
    if s['is_dag']:
         log_success(f"Topology: Directed Acyclic Graph (DAG) - Clean structure")
    else:
         log_warn(f"Topology: Contains cycles (Potential privilege escalation loops detected)")

    log_detail(f"Crown Jewels discovered: {len(s['crown_jewels'])}")
    log_detail(f"Entry Points discovered: {len(s['source_nodes'])}")

    # ---- List nodes ----
    if args.list_nodes:
        print(f"\n{Fore.CYAN}[NODE DIRECTORY]{Style.RESET_ALL}")
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
            log_error(f"Target node '{nid}' (from {label}) missing from graph. Run with --list-nodes to see available IDs.")
            sys.exit(1)

    # ---- 3. Analyze ----
    log_step("PHASE 3", "Executing Security Algorithms")
    t0 = time.time()
    analyzer = SecurityAnalyzer(g)
    reporter = Reporter(analyzer, g)
    t1 = time.time()
    log_success(f"Analysis complete (BFS, Dijkstra, DFS, Centrality, PageRank) ({((t1-t0)*1000):.1f}ms)")

    # ---- 4. Report ----
    log_step("PHASE 4", "Generating Kill Chain Report")
    
    report = reporter.generate_cli_report(
        source=args.source, target=args.target,
        blast_source=args.blast_source, hops=args.blast_hops,
    )
    print("\n" + report)

    # PDF
    if not args.no_pdf:
        reporter.generate_pdf_report(report, output_file=args.pdf)
        log_success(f"PDF Kill Chain Report rendered to: {Fore.WHITE}{args.pdf}{Style.RESET_ALL}")

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
    log_success(f"Machine-readable JSON generated: {Fore.WHITE}{args.export_json}{Style.RESET_ALL}")


def _full_scan(analyzer, cg):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[FULL ATTACK SURFACE SCAN]{Style.RESET_ALL}")
    sources = cg.get_source_nodes()
    targets = cg.get_crown_jewel_nodes()
    if not sources or not targets:
        log_warn("No source/target nodes detected for full scan.")
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
    log_success(f"Interactive HTML Visualization generated: {Fore.WHITE}{out}{Style.RESET_ALL}")
    log_info(f"Open '{out}' in your web browser to explore the cluster graphically.")


def _snapshot(g, analyzer, args):
    from temporal import TemporalAnalyzer
    ta = TemporalAnalyzer(g, analyzer)
    path = ta.save_snapshot(args.source, args.target)
    log_success(f"Cluster snapshot persisted to: {Fore.WHITE}{path}{Style.RESET_ALL}")


def _diff(g, analyzer, args):
    from temporal import TemporalAnalyzer
    ta = TemporalAnalyzer(g, analyzer)
    diff = ta.diff_snapshot(args.diff, args.source, args.target)
    print("\n" + diff["summary"])


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

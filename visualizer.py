"""
visualizer.py — Interactive Attack Graph Visualization (Bonus 1)
=================================================================
Generates a self-contained HTML file using Cytoscape.js to render
the cluster graph in the browser with:
  - Color-coded nodes by entity type
  - Critical attack path highlighted in red
  - Blast radius nodes highlighted in orange
  - Cycle nodes highlighted in purple
  - Interactive zoom, pan, click-to-inspect
  - Animated attack path walkthrough
"""

import json
import os
from typing import Dict, List, Optional

import networkx as nx

from analyzer import SecurityAnalyzer


# ---------------------------------------------------------------------------
# Color palette for node types
# ---------------------------------------------------------------------------
NODE_COLORS: Dict[str, str] = {
    "Internet":       "#ef4444",   # red
    "Service":        "#f97316",   # orange
    "Pod":            "#3b82f6",   # blue
    "ServiceAccount": "#8b5cf6",   # violet
    "Role":           "#06b6d4",   # cyan
    "ClusterRole":    "#0ea5e9",   # sky
    "Secret":         "#eab308",   # yellow
    "ConfigMap":      "#84cc16",   # lime
    "Database":       "#ec4899",   # pink
    "User":           "#14b8a6",   # teal
}

NODE_SHAPES: Dict[str, str] = {
    "Internet":       "diamond",
    "Service":        "round-triangle",
    "Pod":            "round-rectangle",
    "ServiceAccount": "ellipse",
    "Role":           "round-hexagon",
    "ClusterRole":    "round-hexagon",
    "Secret":         "star",
    "ConfigMap":      "rectangle",
    "Database":       "barrel",
    "User":           "vee",
}


def generate_visualization(
    graph: nx.DiGraph,
    analyzer: SecurityAnalyzer,
    source: str,
    target: str,
    blast_source: str,
    blast_hops: int = 3,
    output_file: str = "attack_graph.html",
) -> str:
    """
    Generates a self-contained interactive HTML visualization.

    Returns the output file path.
    """
    # Gather analysis data
    shortest_path, risk_score = analyzer.shortest_path_dijkstra(source, target)
    blast_nodes = set(analyzer.blast_radius_flat(blast_source, blast_hops))
    cycles = analyzer.detect_circular_permissions_dfs()
    cycle_nodes = set(n for cycle in cycles for n in cycle)
    critical_node, _, _ = analyzer.get_critical_node(source, target)
    all_paths = analyzer.all_attack_paths(source, target)

    path_set = set(shortest_path)

    # Build Cytoscape elements
    cy_elements = []

    for node_id, data in graph.nodes(data=True):
        n_type = data.get("type", "Unknown")
        n_name = data.get("name", node_id)
        n_ns = data.get("namespace", "")
        n_cve = data.get("cve", "")
        n_risk = data.get("risk_score", 0.0)
        n_desc = data.get("description", "")

        # Determine visual class
        classes = [n_type.lower()]
        if node_id in path_set:
            classes.append("attack-path")
        if node_id in blast_nodes:
            classes.append("blast-radius")
        if node_id in cycle_nodes:
            classes.append("cycle-member")
        if node_id == critical_node:
            classes.append("critical-node")
        if data.get("is_crown_jewel"):
            classes.append("crown-jewel")
        if node_id == source:
            classes.append("entry-point")

        cy_elements.append({
            "data": {
                "id": node_id,
                "label": f"{n_type}\\n{n_name}",
                "type": n_type,
                "name": n_name,
                "namespace": n_ns,
                "cve": n_cve,
                "risk_score": n_risk,
                "description": n_desc,
                "color": NODE_COLORS.get(n_type, "#94a3b8"),
                "shape": NODE_SHAPES.get(n_type, "ellipse"),
            },
            "classes": " ".join(classes),
        })

    for u, v, data in graph.edges(data=True):
        rel = data.get("relationship", "")
        weight = data.get("weight", 1.0)
        is_attack = (u in path_set and v in path_set and
                     shortest_path.index(v) == shortest_path.index(u) + 1
                     if u in shortest_path and v in shortest_path else False)
        classes = ["attack-edge"] if is_attack else []

        cy_elements.append({
            "data": {
                "id": f"{u}__{v}",
                "source": u,
                "target": v,
                "label": rel,
                "weight": weight,
            },
            "classes": " ".join(classes),
        })

    elements_json = json.dumps(cy_elements, indent=2)
    path_json = json.dumps(shortest_path)
    severity = "CRITICAL" if risk_score >= 9 else "HIGH" if risk_score >= 7 else "MEDIUM"

    html = _HTML_TEMPLATE.replace("__ELEMENTS__", elements_json)
    html = html.replace("__PATH__", path_json)
    html = html.replace("__RISK_SCORE__", f"{risk_score:.1f}")
    html = html.replace("__SEVERITY__", severity)
    html = html.replace("__PATH_HOPS__", str(len(shortest_path) - 1 if shortest_path else 0))
    html = html.replace("__TOTAL_NODES__", str(graph.number_of_nodes()))
    html = html.replace("__TOTAL_EDGES__", str(graph.number_of_edges()))
    html = html.replace("__BLAST_COUNT__", str(len(blast_nodes)))
    html = html.replace("__CYCLE_COUNT__", str(len(cycles)))
    html = html.replace("__ALL_PATHS_COUNT__", str(len(all_paths)))
    html = html.replace("__CRITICAL_NODE__", critical_node or "None")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    return output_file


# ---------------------------------------------------------------------------
# HTML Template with embedded Cytoscape.js
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KUBERUNNER // THREAT TOPOLOGY</title>
<script src="https://cdn.jsdelivr.net/npm/cytoscape@3.28.1/dist/cytoscape.min.js"></script>
<script>
  if (typeof cytoscape === 'undefined') {
    document.write('<script src="https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js"><\/script>');
  }
</script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Orbitron:wght@500;700;900&display=swap');

  :root {
    --bg: #050a0e;
    --panel: #0a1018;
    --border: #0d2137;
    --neon: #00ff9d;
    --amber: #ffb000;
    --threat: #ff2a6d;
    --cyan: #05d9e8;
    --muted: #1a3a4a;
    --text: #c5d1d9;
    --dim: #3a5060;
  }

  * { margin:0; padding:0; box-sizing:border-box; }

  body {
    font-family: 'JetBrains Mono', monospace;
    background: var(--bg); color: var(--text);
    display: flex; flex-direction: column; height: 100vh;
    overflow: hidden;
  }

  /* SCANLINE OVERLAY */
  body::after {
    content: ''; position: fixed; inset: 0; z-index: 9999; pointer-events: none;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,157,0.015) 2px, rgba(0,255,157,0.015) 4px);
  }

  /* HEADER */
  .header {
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    padding: 10px 20px;
    display: flex; align-items: center; justify-content: space-between;
    position: relative;
  }
  .header::before {
    content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, var(--neon), transparent);
    opacity: 0.4;
  }
  .header .brand {
    font-family: 'Orbitron', sans-serif;
    font-size: 16px; font-weight: 900;
    color: var(--neon);
    text-shadow: 0 0 10px rgba(0,255,157,0.3);
    letter-spacing: 3px;
    animation: glitch 4s infinite;
  }
  @keyframes glitch {
    0%, 92%, 100% { opacity: 1; transform: none; }
    93% { opacity: 0.8; transform: translateX(-2px); color: var(--threat); }
    94% { opacity: 1; transform: translateX(1px); color: var(--cyan); }
    95% { opacity: 1; transform: none; color: var(--neon); }
  }
  .header .sub {
    font-size: 9px; color: var(--dim); letter-spacing: 2px;
    text-transform: uppercase; margin-top: 2px;
  }

  /* STATS BAR */
  .metrics {
    display: flex; gap: 0; padding: 0;
    background: var(--panel); border-bottom: 1px solid var(--border);
    font-size: 10px;
  }
  .metric {
    flex: 1; padding: 8px 12px; text-align: center;
    border-right: 1px solid var(--border);
    text-transform: uppercase; letter-spacing: 1px;
    color: var(--dim);
  }
  .metric:last-child { border-right: none; }
  .metric .val {
    font-size: 18px; font-weight: 700;
    font-family: 'Orbitron', sans-serif;
    display: block; margin-top: 2px;
  }
  .val-threat { color: var(--threat); text-shadow: 0 0 8px rgba(255,42,109,0.4); }
  .val-warn { color: var(--amber); text-shadow: 0 0 8px rgba(255,176,0,0.3); }
  .val-ok { color: var(--neon); text-shadow: 0 0 8px rgba(0,255,157,0.3); }
  .val-info { color: var(--cyan); text-shadow: 0 0 8px rgba(5,217,232,0.3); }

  /* MAIN */
  .main { display: flex; flex: 1; overflow: hidden; }

  /* GRAPH AREA */
  #cy {
    flex: 1; background: var(--bg);
    background-image:
      radial-gradient(circle at 50% 50%, rgba(0,255,157,0.02) 0%, transparent 70%),
      linear-gradient(rgba(0,255,157,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,157,0.03) 1px, transparent 1px);
    background-size: 100% 100%, 40px 40px, 40px 40px;
  }

  /* SIDEBAR */
  .sidebar {
    width: 320px; background: var(--panel);
    border-left: 1px solid var(--border);
    overflow-y: auto; padding: 0; font-size: 11px;
  }
  .sidebar::-webkit-scrollbar { width: 4px; }
  .sidebar::-webkit-scrollbar-track { background: var(--bg); }
  .sidebar::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .sb-section {
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
  }
  .sb-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 9px; font-weight: 700;
    color: var(--neon); letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 8px;
    display: flex; align-items: center; gap: 6px;
  }
  .sb-title::before {
    content: ''; width: 3px; height: 12px;
    background: var(--neon); display: inline-block;
  }

  /* KILL CHAIN STEPS */
  .kc-step {
    display: flex; align-items: flex-start; gap: 8px;
    padding: 6px 8px; margin: 3px 0; border-radius: 3px;
    background: rgba(0,255,157,0.03);
    border: 1px solid var(--border);
    transition: all 0.15s;
    cursor: pointer;
  }
  .kc-step:hover {
    border-color: var(--threat);
    background: rgba(255,42,109,0.05);
    box-shadow: 0 0 12px rgba(255,42,109,0.1);
  }
  .kc-num {
    min-width: 20px; height: 20px; border-radius: 2px;
    background: var(--threat); color: #fff;
    display: flex; align-items: center; justify-content: center;
    font-size: 9px; font-weight: 700;
    font-family: 'Orbitron', sans-serif;
  }
  .kc-info { flex: 1; }
  .kc-name { font-weight: 600; color: #e8eff4; font-size: 11px; }
  .kc-detail { color: var(--dim); font-size: 9px; margin-top: 1px; }
  .cve-tag {
    display: inline-block; background: rgba(255,42,109,0.15);
    color: var(--threat); border: 1px solid rgba(255,42,109,0.3);
    padding: 0 5px; border-radius: 2px; font-size: 9px; font-weight: 600;
  }

  /* CONNECTOR LINE */
  .kc-connector {
    width: 1px; height: 6px; background: var(--border);
    margin-left: 17px;
  }

  /* NODE DETAIL */
  .nd-panel {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 3px; padding: 10px;
  }
  .nd-row { display: flex; justify-content: space-between; margin: 2px 0; }
  .nd-label { color: var(--dim); font-size: 9px; text-transform: uppercase; letter-spacing: 1px; }
  .nd-value { color: var(--text); font-size: 10px; font-weight: 500; text-align: right; }

  /* LEGEND */
  .legend-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; }
  .lg-item { display: flex; align-items: center; gap: 5px; font-size: 9px; color: var(--dim); }
  .lg-dot { width: 8px; height: 8px; border-radius: 1px; display: inline-block; }

  /* BUTTONS */
  .btn-row { display: flex; gap: 6px; flex-wrap: wrap; }
  .btn {
    padding: 5px 10px; border-radius: 2px;
    border: 1px solid var(--border);
    background: var(--bg); color: var(--text);
    cursor: pointer; font-size: 9px; font-weight: 500;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase; letter-spacing: 1px;
    transition: all 0.1s;
  }
  .btn:hover { border-color: var(--neon); color: var(--neon); box-shadow: 0 0 8px rgba(0,255,157,0.15); }
  .btn-threat { border-color: rgba(255,42,109,0.4); color: var(--threat); }
  .btn-threat:hover { border-color: var(--threat); box-shadow: 0 0 12px rgba(255,42,109,0.2); }

  /* BOTTOM STATUS BAR */
  .status-bar {
    background: var(--panel); border-top: 1px solid var(--border);
    padding: 4px 20px; font-size: 9px; color: var(--dim);
    display: flex; justify-content: space-between;
    letter-spacing: 1px; text-transform: uppercase;
  }
  .status-bar .live { color: var(--neon); animation: blink 1.5s infinite; }
  @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

  /* PULSE ANIMATION FOR ATTACK PATH NODES */
  @keyframes pulse-threat {
    0%, 100% { box-shadow: 0 0 0 0 rgba(255,42,109,0.4); }
    50% { box-shadow: 0 0 0 8px rgba(255,42,109,0); }
  }
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="brand">KUBERUNNER</div>
    <div class="sub">Threat Topology Visualizer // Attack Surface Mapping</div>
  </div>
  <div class="btn-row">
    <button class="btn btn-threat" onclick="animatePath()">&#9658; SIMULATE ATTACK</button>
    <button class="btn" onclick="resetView()">RESET</button>
    <button class="btn" onclick="toggleLayout()">LAYOUT</button>
  </div>
</div>

<div class="metrics">
  <div class="metric">Nodes<span class="val val-info">__TOTAL_NODES__</span></div>
  <div class="metric">Edges<span class="val val-info">__TOTAL_EDGES__</span></div>
  <div class="metric">Attack Paths<span class="val val-threat">__ALL_PATHS_COUNT__</span></div>
  <div class="metric">Kill Chain Hops<span class="val val-warn">__PATH_HOPS__</span></div>
  <div class="metric">Risk Score<span class="val val-threat">__RISK_SCORE__</span></div>
  <div class="metric">Severity<span class="val val-threat">__SEVERITY__</span></div>
  <div class="metric">Blast Zone<span class="val val-warn">__BLAST_COUNT__</span></div>
  <div class="metric">Cycles<span class="val val-threat">__CYCLE_COUNT__</span></div>
</div>

<div class="main">
  <div id="cy"></div>
  <div class="sidebar">

    <div class="sb-section">
      <div class="sb-title">Kill Chain Trace</div>
      <div id="path-list"></div>
    </div>

    <div class="sb-section">
      <div class="sb-title">Entity Inspector</div>
      <div class="nd-panel" id="node-detail">
        <p style="color:var(--dim); font-size:9px;">[ SELECT NODE TO INSPECT ]</p>
      </div>
    </div>

    <div class="sb-section">
      <div class="sb-title">Entity Legend</div>
      <div class="legend-grid" id="legend"></div>
    </div>

    <div class="sb-section">
      <div class="sb-title">Threat Controls</div>
      <div class="btn-row">
        <button class="btn" onclick="highlightBlast()">BLAST ZONE</button>
        <button class="btn" onclick="highlightCycles()">CYCLES</button>
        <button class="btn" onclick="clearHighlights()">CLEAR</button>
      </div>
    </div>

    <div class="sb-section">
      <div class="sb-title">Critical Chokepoint</div>
      <div class="nd-panel">
        <div class="nd-row"><span class="nd-label">Node</span><span class="nd-value" style="color:var(--threat)">__CRITICAL_NODE__</span></div>
        <div class="nd-row"><span class="nd-label">Action</span><span class="nd-value" style="color:var(--amber)">REMOVE TO SEVER PATHS</span></div>
      </div>
    </div>

  </div>
</div>

<div class="status-bar">
  <span><span class="live">&#9679;</span> KUBERUNNER v2.0 ACTIVE</span>
  <span>MITRE ATT&CK MAPPED // DIJKSTRA + BFS + DFS</span>
  <span>GRAPH ENGINE: NETWORKX 3.2</span>
</div>

<script>
const elements = __ELEMENTS__;
const attackPath = __PATH__;

const cy = cytoscape({
  container: document.getElementById('cy'),
  elements: elements,
  style: [
    {
      selector: 'node',
      style: {
        'label': 'data(label)', 'text-wrap': 'wrap', 'text-max-width': '90px',
        'font-size': '8px', 'font-weight': '500', 'font-family': 'JetBrains Mono, monospace',
        'color': '#8fa5b5', 'text-outline-color': '#050a0e', 'text-outline-width': 2,
        'text-valign': 'bottom', 'text-margin-y': 5,
        'background-color': 'data(color)', 'shape': 'data(shape)',
        'width': 30, 'height': 30, 'border-width': 1.5, 'border-color': '#1a3a4a',
      }
    },
    { selector: 'node.attack-path', style: {
        'border-color': '#ff2a6d', 'border-width': 2.5, 'width': 40, 'height': 40,
    }},
    { selector: 'node.crown-jewel', style: {
        'border-color': '#ffb000', 'border-width': 3, 'width': 46, 'height': 46,
    }},
    { selector: 'node.entry-point', style: {
        'border-color': '#00ff9d', 'border-width': 3, 'width': 46, 'height': 46,
    }},
    { selector: 'node.critical-node', style: {
        'border-color': '#c084fc', 'border-width': 3, 'border-style': 'double',
    }},
    { selector: 'node.blast-highlight', style: {
        'background-opacity': 0.9, 'border-color': '#ffb000', 'border-width': 3,
    }},
    { selector: 'node.cycle-highlight', style: {
        'border-color': '#c084fc', 'border-width': 3, 'border-style': 'dashed',
    }},
    { selector: 'node.animate-step', style: {
        'background-color': '#ff2a6d', 'border-color': '#ffb000', 'border-width': 4,
        'width': 50, 'height': 50, 'z-index': 999,
    }},
    { selector: 'edge', style: {
        'width': 1, 'line-color': '#0d2137', 'target-arrow-color': '#1a3a4a',
        'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
        'label': 'data(label)', 'font-size': '6px', 'font-family': 'JetBrains Mono, monospace',
        'color': '#1a3a4a', 'text-rotation': 'autorotate', 'text-margin-y': -6,
    }},
    { selector: 'edge.attack-edge', style: {
        'width': 2.5, 'line-color': '#ff2a6d', 'target-arrow-color': '#ff2a6d',
        'line-style': 'solid', 'z-index': 999,
    }},
    { selector: 'node.dimmed', style: { 'opacity': 0.1 } },
    { selector: 'edge.dimmed', style: { 'opacity': 0.05 } },
  ],
  layout: {
    name: 'cose', animate: true, animationDuration: 1000,
    nodeRepulsion: 9000, idealEdgeLength: 130, gravity: 0.25,
  },
  minZoom: 0.15, maxZoom: 3.5,
});

// --- Kill Chain List ---
const pathList = document.getElementById('path-list');
attackPath.forEach((nodeId, i) => {
  const n = cy.getElementById(nodeId);
  const d = n.data();
  if (i > 0) pathList.innerHTML += '<div class="kc-connector"></div>';
  let html = '<div class="kc-step" onmouseover="highlightNode(\'' + nodeId + '\')" onmouseout="unhighlightNode(\'' + nodeId + '\')">';
  html += '<div class="kc-num">' + (i+1) + '</div>';
  html += '<div class="kc-info"><div class="kc-name">' + (d.type||'') + ' : ' + (d.name||nodeId) + '</div>';
  html += '<div class="kc-detail">' + (d.namespace ? d.namespace : '-');
  if (d.cve) html += ' <span class="cve-tag">' + d.cve + '</span>';
  html += '</div></div></div>';
  pathList.innerHTML += html;
});

// --- Legend ---
const legend = document.getElementById('legend');
const types = {"Internet":"#ef4444","Service":"#f97316","Pod":"#3b82f6","ServiceAccount":"#8b5cf6",
  "Role":"#06b6d4","ClusterRole":"#0ea5e9","Secret":"#eab308","ConfigMap":"#84cc16",
  "Database":"#ec4899","User":"#14b8a6"};
Object.entries(types).forEach(([t,c]) => {
  legend.innerHTML += '<div class="lg-item"><span class="lg-dot" style="background:'+c+'"></span>'+t+'</div>';
});

// --- Node click ---
cy.on('tap', 'node', function(evt) {
  const d = evt.target.data();
  const det = document.getElementById('node-detail');
  det.innerHTML = `
    <div class="nd-row"><span class="nd-label">ID</span><span class="nd-value">${d.id}</span></div>
    <div class="nd-row"><span class="nd-label">Type</span><span class="nd-value">${d.type}</span></div>
    <div class="nd-row"><span class="nd-label">Name</span><span class="nd-value">${d.name}</span></div>
    <div class="nd-row"><span class="nd-label">Namespace</span><span class="nd-value">${d.namespace || '-'}</span></div>
    <div class="nd-row"><span class="nd-label">Risk</span><span class="nd-value" style="color:var(--threat)">${d.risk_score}</span></div>
    ${d.cve ? '<div class="nd-row"><span class="nd-label">CVE</span><span class="nd-value"><span class="cve-tag">'+d.cve+'</span></span></div>' : ''}
    <div class="nd-row"><span class="nd-label">Desc</span><span class="nd-value" style="font-size:9px">${d.description || '-'}</span></div>
  `;
});

// --- Functions ---
let currentLayout = 'cose';
function toggleLayout() {
  currentLayout = currentLayout === 'cose' ? 'breadthfirst' : 'cose';
  const opts = currentLayout === 'breadthfirst'
    ? { name:'breadthfirst', directed:true, spacingFactor:1.3, animate:true, animationDuration:700, roots: attackPath.length ? '#'+attackPath[0] : undefined }
    : { name:'cose', animate:true, animationDuration:1000, nodeRepulsion:9000, idealEdgeLength:130, gravity:0.25 };
  cy.layout(opts).run();
}
function resetView() { cy.fit(undefined, 40); clearHighlights(); }
function clearHighlights() { cy.elements().removeClass('dimmed blast-highlight cycle-highlight animate-step'); }
function highlightBlast() {
  clearHighlights();
  const b = cy.elements('node.blast-radius');
  cy.elements().not(b).not(b.connectedEdges()).addClass('dimmed');
  b.addClass('blast-highlight');
}
function highlightCycles() {
  clearHighlights();
  const c = cy.elements('node.cycle-member');
  cy.elements().not(c).not(c.connectedEdges()).addClass('dimmed');
  c.addClass('cycle-highlight');
}
function highlightNode(id) { cy.getElementById(id).style({'border-color':'#ffb000','border-width':4}); }
function unhighlightNode(id) { cy.getElementById(id).removeStyle('border-color border-width'); }
function animatePath() {
  clearHighlights(); cy.elements().addClass('dimmed');
  let i = 0;
  function step() {
    if (i >= attackPath.length) return;
    const node = cy.getElementById(attackPath[i]);
    node.removeClass('dimmed').addClass('animate-step');
    if (i > 0) {
      const edge = cy.edges('[source="'+attackPath[i-1]+'"][target="'+attackPath[i]+'"]');
      edge.removeClass('dimmed').style({'line-color':'#ff2a6d','target-arrow-color':'#ff2a6d','width':3});
    }
    cy.animate({ center: { eles: node }, duration: 350 });
    i++; setTimeout(step, 700);
  }
  step();
}
</script>
</body>
</html>
"""

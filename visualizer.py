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
<title>K8s Attack Path Visualizer</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0f172a; color: #e2e8f0;
    display: flex; flex-direction: column; height: 100vh;
  }
  .header {
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid #334155;
    padding: 12px 24px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .header h1 {
    font-size: 18px; font-weight: 700;
    background: linear-gradient(90deg, #ef4444, #f97316);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }
  .header .subtitle { font-size: 12px; color: #64748b; }
  .stats-bar {
    display: flex; gap: 16px; padding: 8px 24px;
    background: #1e293b; border-bottom: 1px solid #334155;
    font-size: 12px; flex-wrap: wrap;
  }
  .stat { display: flex; align-items: center; gap: 6px; }
  .stat-value {
    font-weight: 700; font-size: 14px;
    padding: 2px 8px; border-radius: 6px;
  }
  .stat-critical { background: #7f1d1d; color: #fca5a5; }
  .stat-warn { background: #78350f; color: #fbbf24; }
  .stat-info { background: #1e3a5f; color: #7dd3fc; }
  .stat-ok { background: #14532d; color: #86efac; }

  .main-container { display: flex; flex: 1; overflow: hidden; }

  #cy { flex: 1; background: #0f172a; }

  .sidebar {
    width: 340px; background: #1e293b; border-left: 1px solid #334155;
    overflow-y: auto; padding: 16px; font-size: 13px;
  }
  .sidebar h3 {
    font-size: 13px; text-transform: uppercase; letter-spacing: 1px;
    color: #94a3b8; margin: 16px 0 8px 0; border-bottom: 1px solid #334155;
    padding-bottom: 4px;
  }
  .sidebar h3:first-child { margin-top: 0; }

  .path-step {
    display: flex; align-items: flex-start; gap: 8px;
    padding: 6px 8px; margin: 2px 0; border-radius: 6px;
    background: #0f172a; border: 1px solid #334155;
    transition: all 0.2s;
  }
  .path-step:hover { border-color: #ef4444; }
  .path-step .step-num {
    min-width: 22px; height: 22px; border-radius: 50%;
    background: #ef4444; color: white;
    display: flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 700;
  }
  .path-step .step-info { flex: 1; }
  .path-step .step-name { font-weight: 600; color: #f1f5f9; }
  .path-step .step-detail { color: #94a3b8; font-size: 11px; }
  .cve-tag {
    display: inline-block; background: #7f1d1d; color: #fca5a5;
    padding: 1px 6px; border-radius: 4px; font-size: 10px; font-weight: 600;
  }

  .legend { display: flex; flex-wrap: wrap; gap: 6px; }
  .legend-item {
    display: flex; align-items: center; gap: 4px;
    font-size: 11px; color: #94a3b8;
  }
  .legend-dot {
    width: 10px; height: 10px; border-radius: 50%;
    display: inline-block;
  }

  .node-detail {
    background: #0f172a; border: 1px solid #334155;
    border-radius: 8px; padding: 12px; margin-top: 8px;
  }
  .node-detail .nd-row { display: flex; justify-content: space-between; margin: 3px 0; }
  .node-detail .nd-label { color: #64748b; font-size: 11px; }
  .node-detail .nd-value { color: #e2e8f0; font-size: 12px; font-weight: 500; }

  .controls {
    display: flex; gap: 8px; margin-top: 8px;
  }
  .btn {
    padding: 6px 14px; border-radius: 6px; border: 1px solid #475569;
    background: #334155; color: #e2e8f0; cursor: pointer;
    font-size: 12px; font-weight: 500;
    transition: all 0.15s;
  }
  .btn:hover { background: #475569; }
  .btn-danger { background: #7f1d1d; border-color: #991b1b; }
  .btn-danger:hover { background: #991b1b; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>Kubernetes Attack Path Visualizer</h1>
    <div class="subtitle">Graph-Based Security Analysis for Cloud-Native Infrastructure</div>
  </div>
  <div style="display:flex; gap:8px;">
    <button class="btn btn-danger" onclick="animatePath()">Animate Attack</button>
    <button class="btn" onclick="resetView()">Reset View</button>
    <button class="btn" onclick="toggleLayout()">Toggle Layout</button>
  </div>
</div>

<div class="stats-bar">
  <div class="stat">Nodes: <span class="stat-value stat-info">__TOTAL_NODES__</span></div>
  <div class="stat">Edges: <span class="stat-value stat-info">__TOTAL_EDGES__</span></div>
  <div class="stat">Attack Paths: <span class="stat-value stat-critical">__ALL_PATHS_COUNT__</span></div>
  <div class="stat">Shortest Path Hops: <span class="stat-value stat-warn">__PATH_HOPS__</span></div>
  <div class="stat">Risk Score: <span class="stat-value stat-critical">__RISK_SCORE__ (__SEVERITY__)</span></div>
  <div class="stat">Blast Radius: <span class="stat-value stat-warn">__BLAST_COUNT__</span></div>
  <div class="stat">Cycles: <span class="stat-value stat-critical">__CYCLE_COUNT__</span></div>
  <div class="stat">Critical Node: <span class="stat-value stat-critical">__CRITICAL_NODE__</span></div>
</div>

<div class="main-container">
  <div id="cy"></div>
  <div class="sidebar" id="sidebar">
    <h3>Attack Kill Chain</h3>
    <div id="path-list"></div>

    <h3>Node Detail</h3>
    <div class="node-detail" id="node-detail">
      <p style="color:#64748b">Click a node on the graph to inspect.</p>
    </div>

    <h3>Legend</h3>
    <div class="legend" id="legend"></div>

    <h3>Controls</h3>
    <div class="controls">
      <button class="btn" onclick="highlightBlast()">Show Blast Zone</button>
      <button class="btn" onclick="highlightCycles()">Show Cycles</button>
      <button class="btn" onclick="clearHighlights()">Clear</button>
    </div>
  </div>
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
        'label': 'data(label)',
        'text-wrap': 'wrap',
        'text-max-width': '100px',
        'font-size': '9px',
        'font-weight': '500',
        'color': '#e2e8f0',
        'text-outline-color': '#0f172a',
        'text-outline-width': 2,
        'text-valign': 'bottom',
        'text-margin-y': 5,
        'background-color': 'data(color)',
        'shape': 'data(shape)',
        'width': 35,
        'height': 35,
        'border-width': 2,
        'border-color': '#334155',
      }
    },
    {
      selector: 'node.attack-path',
      style: {
        'border-color': '#ef4444',
        'border-width': 3,
        'width': 45,
        'height': 45,
      }
    },
    {
      selector: 'node.crown-jewel',
      style: {
        'border-color': '#f59e0b',
        'border-width': 4,
        'width': 50,
        'height': 50,
      }
    },
    {
      selector: 'node.entry-point',
      style: {
        'border-color': '#22c55e',
        'border-width': 4,
        'width': 50,
        'height': 50,
      }
    },
    {
      selector: 'node.critical-node',
      style: {
        'border-color': '#a855f7',
        'border-width': 4,
        'border-style': 'double',
      }
    },
    {
      selector: 'node.blast-highlight',
      style: {
        'background-opacity': 0.9,
        'border-color': '#fb923c',
        'border-width': 3,
      }
    },
    {
      selector: 'node.cycle-highlight',
      style: {
        'border-color': '#c084fc',
        'border-width': 4,
        'border-style': 'dashed',
      }
    },
    {
      selector: 'node.animate-step',
      style: {
        'background-color': '#ef4444',
        'border-color': '#fbbf24',
        'border-width': 5,
        'width': 55,
        'height': 55,
        'z-index': 999,
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 1.5,
        'line-color': '#475569',
        'target-arrow-color': '#475569',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '7px',
        'color': '#64748b',
        'text-rotation': 'autorotate',
        'text-margin-y': -8,
      }
    },
    {
      selector: 'edge.attack-edge',
      style: {
        'width': 3,
        'line-color': '#ef4444',
        'target-arrow-color': '#ef4444',
        'line-style': 'solid',
        'z-index': 999,
      }
    },
    {
      selector: 'node.dimmed',
      style: { 'opacity': 0.15 }
    },
    {
      selector: 'edge.dimmed',
      style: { 'opacity': 0.08 }
    },
  ],
  layout: {
    name: 'cose',
    animate: true,
    animationDuration: 800,
    nodeRepulsion: 8000,
    idealEdgeLength: 120,
    gravity: 0.3,
  },
  minZoom: 0.2,
  maxZoom: 3,
});

// --- Path list ---
const pathList = document.getElementById('path-list');
attackPath.forEach((nodeId, i) => {
  const n = cy.getElementById(nodeId);
  const d = n.data();
  let html = '<div class="path-step" onmouseover="highlightNode(\'' + nodeId + '\')" onmouseout="unhighlightNode(\'' + nodeId + '\')">';
  html += '<div class="step-num">' + (i+1) + '</div>';
  html += '<div class="step-info">';
  html += '<div class="step-name">' + (d.type || '') + ': ' + (d.name || nodeId) + '</div>';
  html += '<div class="step-detail">' + (d.namespace ? 'ns: ' + d.namespace : '');
  if (d.cve) html += ' <span class="cve-tag">' + d.cve + ' (CVSS ' + d.risk_score + ')</span>';
  html += '</div></div></div>';
  pathList.innerHTML += html;
});

// --- Legend ---
const legend = document.getElementById('legend');
const types = {"Internet":"#ef4444","Service":"#f97316","Pod":"#3b82f6","ServiceAccount":"#8b5cf6",
  "Role":"#06b6d4","ClusterRole":"#0ea5e9","Secret":"#eab308","ConfigMap":"#84cc16",
  "Database":"#ec4899","User":"#14b8a6"};
Object.entries(types).forEach(([t,c]) => {
  legend.innerHTML += '<div class="legend-item"><span class="legend-dot" style="background:'+c+'"></span>'+t+'</div>';
});
legend.innerHTML += '<div class="legend-item"><span class="legend-dot" style="border:2px solid #ef4444; background:transparent"></span>Attack Path</div>';
legend.innerHTML += '<div class="legend-item"><span class="legend-dot" style="border:2px solid #22c55e; background:transparent"></span>Entry Point</div>';
legend.innerHTML += '<div class="legend-item"><span class="legend-dot" style="border:2px solid #f59e0b; background:transparent"></span>Crown Jewel</div>';

// --- Node click ---
cy.on('tap', 'node', function(evt) {
  const d = evt.target.data();
  const det = document.getElementById('node-detail');
  det.innerHTML = `
    <div class="nd-row"><span class="nd-label">ID</span><span class="nd-value">${d.id}</span></div>
    <div class="nd-row"><span class="nd-label">Type</span><span class="nd-value">${d.type}</span></div>
    <div class="nd-row"><span class="nd-label">Name</span><span class="nd-value">${d.name}</span></div>
    <div class="nd-row"><span class="nd-label">Namespace</span><span class="nd-value">${d.namespace}</span></div>
    <div class="nd-row"><span class="nd-label">Risk Score</span><span class="nd-value">${d.risk_score}</span></div>
    ${d.cve ? '<div class="nd-row"><span class="nd-label">CVE</span><span class="nd-value"><span class="cve-tag">'+d.cve+'</span></span></div>' : ''}
    <div class="nd-row"><span class="nd-label">Description</span><span class="nd-value" style="font-size:11px">${d.description || 'N/A'}</span></div>
  `;
});

// --- Functions ---
let currentLayout = 'cose';
function toggleLayout() {
  currentLayout = currentLayout === 'cose' ? 'breadthfirst' : 'cose';
  const opts = currentLayout === 'breadthfirst'
    ? { name: 'breadthfirst', directed: true, spacingFactor: 1.2, animate: true, animationDuration: 600, roots: attackPath.length ? '#' + attackPath[0] : undefined }
    : { name: 'cose', animate: true, animationDuration: 800, nodeRepulsion: 8000, idealEdgeLength: 120, gravity: 0.3 };
  cy.layout(opts).run();
}

function resetView() { cy.fit(undefined, 40); clearHighlights(); }

function clearHighlights() {
  cy.elements().removeClass('dimmed blast-highlight cycle-highlight animate-step');
}

function highlightBlast() {
  clearHighlights();
  const blastNodes = cy.elements('node.blast-radius');
  cy.elements().not(blastNodes).not(blastNodes.connectedEdges()).addClass('dimmed');
  blastNodes.addClass('blast-highlight');
}

function highlightCycles() {
  clearHighlights();
  const cycleNodes = cy.elements('node.cycle-member');
  cy.elements().not(cycleNodes).not(cycleNodes.connectedEdges()).addClass('dimmed');
  cycleNodes.addClass('cycle-highlight');
}

function highlightNode(id) { cy.getElementById(id).style({'border-color': '#fbbf24', 'border-width': 5}); }
function unhighlightNode(id) { cy.getElementById(id).removeStyle('border-color border-width'); }

function animatePath() {
  clearHighlights();
  cy.elements().addClass('dimmed');
  let i = 0;
  function step() {
    if (i >= attackPath.length) return;
    const node = cy.getElementById(attackPath[i]);
    node.removeClass('dimmed').addClass('animate-step');
    if (i > 0) {
      const edge = cy.edges('[source="'+attackPath[i-1]+'"][target="'+attackPath[i]+'"]');
      edge.removeClass('dimmed').style({'line-color':'#ef4444','target-arrow-color':'#ef4444','width':4});
    }
    cy.animate({ center: { eles: node }, duration: 300 });
    i++;
    setTimeout(step, 600);
  }
  step();
}
</script>
</body>
</html>
"""

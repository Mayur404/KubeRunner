"""
simulator.py — Attack Simulation Engine
=========================================
Simulates a realistic attacker traversal through the cluster graph,
generating a step-by-step narrative with:
  - Attacker decision rationale at each hop
  - Time estimates per exploitation step
  - Cumulative privilege level tracking
  - MITRE ATT&CK technique references
  - Difficulty assessment per step

This is NOT a simple path listing — it models how a real adversary
thinks and moves through a Kubernetes environment.
"""

import datetime
from typing import Dict, List, Optional, Tuple

import networkx as nx

from analyzer import SecurityAnalyzer
from mitre_mapper import MITREMapper


# ---------------------------------------------------------------------------
# Privilege Levels (cumulative — attacker accumulates these)
# ---------------------------------------------------------------------------
PRIV_LEVELS = {
    "Internet":       0,  # No access
    "Service":        1,  # Network access only
    "Pod":            2,  # Container-level access
    "ServiceAccount": 3,  # API server identity
    "Role":           4,  # Namespace-scoped RBAC
    "ClusterRole":    5,  # Cluster-wide RBAC
    "ConfigMap":      3,  # Configuration data access
    "Secret":         6,  # Credential access
    "Database":       7,  # Crown jewel — data access
    "User":           2,  # Authenticated human
}

# Estimated time for each relationship exploitation
TIME_ESTIMATES = {
    "routes-traffic-to":       "~2 minutes (network scan + exploit delivery)",
    "uses-service-account":    "~30 seconds (read mounted SA token from /var/run/secrets)",
    "bound-to":                "~10 seconds (automatic — RBAC binding is pre-existing)",
    "can-read":                "~15 seconds (kubectl get secret -o json)",
    "can-write":               "~15 seconds (kubectl edit configmap)",
    "grants-admin-to":         "~10 seconds (automatic — admin binding is pre-existing)",
    "grants-full-access-to":   "~10 seconds (automatic — cluster-admin binding)",
    "can-exec":                "~20 seconds (kubectl exec -it pod -- /bin/sh)",
    "can-impersonate":         "~30 seconds (kubectl --as=target-sa get secrets)",
    "authenticates-to":        "~45 seconds (extract creds, connect to database)",
    "accesses-backup-of":      "~60 seconds (download and decrypt backup file)",
    "stores-state-in":         "~30 seconds (access etcd via API server)",
    "mounts-hostpath":         "~20 seconds (read host filesystem via volume mount)",
    "can-exec-on-nodes":       "~45 seconds (SSH or kubectl debug node)",
    "can-configure":           "~30 seconds (modify infrastructure configuration)",
}

# Decision rationale templates
DECISION_TEMPLATES = {
    "routes-traffic-to":       "Attacker identifies {target_name} as an exploitable service endpoint. Network scan reveals open port with {cve_info}.",
    "uses-service-account":    "Inside the compromised container, the attacker reads the mounted ServiceAccount token from /var/run/secrets/kubernetes.io/serviceaccount/token.",
    "bound-to":                "The stolen SA token is bound to {target_name} — the attacker now inherits all permissions granted by this role.",
    "can-read":                "With role permissions, the attacker queries the Kubernetes API: `kubectl get secret {target_name} -o json` to extract credentials.",
    "can-write":               "The attacker modifies {target_name} to inject a malicious configuration, enabling persistence.",
    "grants-admin-to":         "A dangerous admin grant gives the attacker full control over {target_name} without any additional authentication.",
    "grants-full-access-to":   "Cluster-admin binding grants unrestricted access. The attacker can now control the entire cluster.",
    "can-exec":                "The attacker uses `kubectl exec -it {target_name} -- /bin/sh` to get a shell inside the target container.",
    "can-impersonate":         "Using SA impersonation, the attacker runs `kubectl --as={target_name}` to assume a higher-privilege identity.",
    "authenticates-to":        "Using the extracted credentials, the attacker connects directly to {target_name} and gains full data access.",
    "accesses-backup-of":      "The attacker downloads backup data for {target_name}, containing a complete copy of historical records.",
    "stores-state-in":         "Through the API server, the attacker accesses {target_name} which stores all cluster state including secrets.",
    "mounts-hostpath":         "A hostPath mount exposes the host filesystem. The attacker reads {target_name} directly from the node.",
    "can-exec-on-nodes":       "Node management privileges allow the attacker to execute commands directly on cluster worker nodes.",
    "can-configure":           "Admin access enables the attacker to reconfigure {target_name}, potentially disabling security controls.",
}


class AttackSimulator:
    """
    Simulates a step-by-step attacker traversal with realistic narrative,
    decision rationale, timing, and privilege escalation tracking.
    """

    def __init__(self, graph: nx.DiGraph, analyzer: SecurityAnalyzer):
        self.graph = graph
        self.analyzer = analyzer
        self.mitre = MITREMapper()

    def simulate_attack(self, source: str, target: str) -> Dict:
        """
        Runs a full attack simulation from source to target.
        Returns a dict with the complete simulation results.
        """
        path, risk_score = self.analyzer.shortest_path_dijkstra(source, target)
        if not path:
            return {"success": False, "message": f"No attack path from {source} to {target}"}

        mitre_mappings = self.mitre.map_attack_path(self.graph, path)
        steps = []
        cumulative_priv = 0
        total_time_sec = 0

        for i in range(len(path)):
            node_id = path[i]
            node_data = self.graph.nodes.get(node_id, {})
            n_type = node_data.get("type", "Unknown")
            n_name = node_data.get("name", node_id)
            priv = PRIV_LEVELS.get(n_type, 0)
            cumulative_priv = max(cumulative_priv, priv)

            step: Dict = {
                "step": i + 1,
                "node_id": node_id,
                "node_type": n_type,
                "node_name": n_name,
                "namespace": node_data.get("namespace", ""),
                "privilege_level": cumulative_priv,
                "privilege_label": self._priv_label(cumulative_priv),
            }

            if i == 0:
                step["action"] = "INITIAL COMPROMISE"
                step["narrative"] = f"The attacker begins from {n_type}:{n_name}, a public-facing entry point with no authentication required."
                step["time_estimate"] = "0 seconds (starting position)"
                step["difficulty"] = "TRIVIAL"
            else:
                prev_node = path[i - 1]
                edge_data = self.graph.edges.get((prev_node, node_id), {})
                rel = edge_data.get("relationship", "unknown")
                weight = edge_data.get("weight", 1.0)

                cve = node_data.get("cve", "")
                cve_info = f"a known vulnerability ({cve}, CVSS {node_data.get('risk_score', 0.0)})" if cve else "a potential misconfiguration"

                narrative_tmpl = DECISION_TEMPLATES.get(rel, "The attacker moves laterally to {target_name}.")
                narrative = narrative_tmpl.format(
                    target_name=f"{n_type}:{n_name}",
                    cve_info=cve_info,
                )

                time_est = TIME_ESTIMATES.get(rel, "~30 seconds")
                time_sec = self._parse_time(time_est)
                total_time_sec += time_sec

                difficulty = "TRIVIAL" if weight <= 1.5 else "EASY" if weight <= 3 else "MODERATE" if weight <= 6 else "HARD"

                mitre_info = mitre_mappings[i - 1] if i - 1 < len(mitre_mappings) else {}

                step["action"] = f"LATERAL MOVEMENT via {rel}"
                step["relationship"] = rel
                step["narrative"] = narrative
                step["time_estimate"] = time_est
                step["difficulty"] = difficulty
                step["cve"] = cve
                step["mitre_technique"] = f"{mitre_info.get('mitre_id', 'N/A')} - {mitre_info.get('mitre_name', 'Unknown')}"
                step["mitre_tactic"] = mitre_info.get("tactic", "Unknown")

            steps.append(step)

        return {
            "success": True,
            "source": source,
            "target": target,
            "total_steps": len(steps),
            "total_risk_score": risk_score,
            "severity": self.analyzer.risk_rating(risk_score),
            "estimated_total_time": self._format_time(total_time_sec),
            "final_privilege_level": self._priv_label(cumulative_priv),
            "steps": steps,
        }

    def format_simulation_report(self, result: Dict) -> str:
        """Formats the simulation result into a readable narrative report."""
        if not result.get("success"):
            return f"  [OK] {result.get('message', 'No attack path found.')}"

        lines = []
        lines.append(f"  {'=' * 65}")
        lines.append(f"  ATTACK SIMULATION — ADVERSARY PERSPECTIVE")
        lines.append(f"  {'=' * 65}")
        lines.append(f"")
        lines.append(f"  Objective   : Reach {result['target']} from {result['source']}")
        lines.append(f"  Est. Time   : {result['estimated_total_time']}")
        lines.append(f"  Risk Score  : {result['total_risk_score']:.1f} ({result['severity']})")
        lines.append(f"  Final Access: {result['final_privilege_level']}")
        lines.append(f"")

        for step in result["steps"]:
            step_num = step["step"]
            action = step["action"]
            node = f"{step['node_type']}:{step['node_name']}"
            ns = step.get("namespace", "")
            priv = step["privilege_label"]

            lines.append(f"  --- Step {step_num}: {action} ---")
            lines.append(f"  Target     : {node} (ns: {ns})")
            lines.append(f"  Privilege  : {priv}")
            lines.append(f"  Time       : {step.get('time_estimate', 'N/A')}")

            if step.get("difficulty"):
                lines.append(f"  Difficulty : {step['difficulty']}")
            if step.get("cve"):
                lines.append(f"  CVE        : {step['cve']}")
            if step.get("mitre_technique"):
                lines.append(f"  ATT&CK     : {step['mitre_technique']}")

            lines.append(f"")
            lines.append(f"  > {step['narrative']}")
            lines.append(f"")

        lines.append(f"  {'=' * 65}")
        lines.append(f"  SIMULATION COMPLETE — Crown jewel '{result['target']}' compromised.")
        lines.append(f"  Total exploitation time: {result['estimated_total_time']}")
        lines.append(f"  {'=' * 65}")

        return "\n".join(lines)

    # Helpers
    def _priv_label(self, level: int) -> str:
        labels = {
            0: "NONE (Anonymous)",
            1: "NETWORK (External access)",
            2: "CONTAINER (Pod-level shell)",
            3: "API-AUTHENTICATED (SA token)",
            4: "RBAC-NAMESPACE (Role permissions)",
            5: "RBAC-CLUSTER (Cluster-wide admin)",
            6: "CREDENTIAL (Secret access)",
            7: "DATA-OWNER (Database access)",
        }
        return labels.get(level, f"LEVEL-{level}")

    def _parse_time(self, time_str: str) -> int:
        if "minute" in time_str:
            try:
                return int(time_str.split("~")[1].split(" ")[0]) * 60
            except (IndexError, ValueError):
                return 120
        try:
            return int(time_str.split("~")[1].split(" ")[0])
        except (IndexError, ValueError):
            return 30

    def _format_time(self, total_sec: int) -> str:
        if total_sec < 60:
            return f"{total_sec} seconds"
        minutes = total_sec // 60
        secs = total_sec % 60
        return f"{minutes}m {secs}s"

"""
mitre_mapper.py — MITRE ATT&CK for Containers Mapping
=======================================================
Maps each relationship type in the attack graph to the corresponding
MITRE ATT&CK for Containers technique ID and name.

Reference: https://attack.mitre.org/matrices/enterprise/containers/
"""

from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# MITRE ATT&CK for Containers — Technique Mapping
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    # Tactic: Initial Access
    "routes-traffic-to": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversary exploits a vulnerability in an internet-facing service to gain initial access.",
        "mitigations": [
            "Apply web application firewalls (WAF)",
            "Patch known CVEs in ingress controllers",
            "Implement network segmentation"
        ],
    },
    # Tactic: Execution
    "can-exec": {
        "id": "T1609",
        "name": "Container Administration Command",
        "tactic": "Execution",
        "description": "Adversary uses kubectl exec or similar to execute commands inside a container.",
        "mitigations": [
            "Restrict kubectl exec permissions via RBAC",
            "Enable audit logging for exec events",
            "Use PodSecurityPolicies to limit container capabilities"
        ],
    },
    # Tactic: Persistence / Privilege Escalation
    "uses-service-account": {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation",
        "description": "Pod uses a service account token to authenticate to the API server.",
        "mitigations": [
            "Apply least-privilege service account bindings",
            "Disable automounting of SA tokens where not needed",
            "Rotate service account tokens regularly"
        ],
    },
    "can-impersonate": {
        "id": "T1550.001",
        "name": "Use Alternate Authentication Material",
        "tactic": "Privilege Escalation",
        "description": "Adversary impersonates another service account to escalate privileges.",
        "mitigations": [
            "Restrict impersonation verbs in RBAC policies",
            "Audit impersonation events in cluster logs",
            "Implement admission controllers to validate identity"
        ],
    },
    # Tactic: Credential Access
    "can-read": {
        "id": "T1552.007",
        "name": "Unsecured Credentials: Container API",
        "tactic": "Credential Access",
        "description": "Adversary reads secrets from the Kubernetes API via RBAC permissions.",
        "mitigations": [
            "Encrypt secrets at rest using KMS providers",
            "Restrict secret read access to minimum required SAs",
            "Use external secret managers (Vault, AWS Secrets Manager)"
        ],
    },
    "mounts-hostpath": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "Privilege Escalation",
        "description": "Container with hostPath volume mount can access host filesystem.",
        "mitigations": [
            "Prohibit hostPath mounts via PodSecurityPolicies",
            "Use read-only filesystem where possible",
            "Implement OPA/Gatekeeper policies"
        ],
    },
    # Tactic: Discovery
    "bound-to": {
        "id": "T1613",
        "name": "Container and Resource Discovery",
        "tactic": "Discovery",
        "description": "Role binding grants access to discover and enumerate cluster resources.",
        "mitigations": [
            "Apply least-privilege RBAC bindings",
            "Audit role bindings regularly",
            "Remove unused role bindings"
        ],
    },
    # Tactic: Lateral Movement
    "authenticates-to": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Credentials obtained from secrets are used to authenticate to databases or services.",
        "mitigations": [
            "Rotate database credentials frequently",
            "Use short-lived tokens instead of static passwords",
            "Implement mutual TLS for database connections"
        ],
    },
    "accesses-backup-of": {
        "id": "T1530",
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Adversary accesses backup storage using compromised credentials.",
        "mitigations": [
            "Restrict backup access to dedicated service accounts",
            "Encrypt backups at rest and in transit",
            "Monitor access to backup storage buckets"
        ],
    },
    # Tactic: Impact
    "grants-admin-to": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Mutual admin grants create a privilege escalation loop.",
        "mitigations": [
            "Audit admin role bindings for circular dependencies",
            "Implement separation of duties",
            "Use break-glass procedures for admin access"
        ],
    },
    "grants-full-access-to": {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation",
        "description": "ClusterRole grants unrestricted access to the API server.",
        "mitigations": [
            "Avoid using cluster-admin role for workloads",
            "Implement just-in-time access provisioning",
            "Alert on cluster-admin usage"
        ],
    },
    "can-write": {
        "id": "T1565.001",
        "name": "Data Manipulation: Stored Data",
        "tactic": "Impact",
        "description": "Write access to ConfigMaps enables configuration poisoning.",
        "mitigations": [
            "Restrict ConfigMap write access to CI/CD pipelines only",
            "Implement change approval workflows",
            "Enable ConfigMap versioning and audit logging"
        ],
    },
    "stores-state-in": {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "API server stores all cluster state in etcd — compromise grants total control.",
        "mitigations": [
            "Encrypt etcd data at rest",
            "Restrict etcd access to API server only",
            "Enable etcd authentication and TLS"
        ],
    },
    "can-exec-on-nodes": {
        "id": "T1609",
        "name": "Container Administration Command",
        "tactic": "Execution",
        "description": "Node management role grants execution capabilities on cluster nodes.",
        "mitigations": [
            "Restrict node management to dedicated infrastructure SAs",
            "Implement jump-box access patterns",
            "Audit all node-level operations"
        ],
    },
    "can-configure": {
        "id": "T1578",
        "name": "Modify Cloud Compute Infrastructure",
        "tactic": "Defense Evasion",
        "description": "Admin access allows reconfiguration of compute resources.",
        "mitigations": [
            "Implement infrastructure-as-code with drift detection",
            "Restrict modify permissions to CI/CD pipelines",
            "Enable change tracking and alerting"
        ],
    },
}


class MITREMapper:
    """
    Maps attack path edges to MITRE ATT&CK for Containers techniques.
    """

    @staticmethod
    def map_relationship(relationship: str) -> Optional[Dict[str, str]]:
        """Returns MITRE ATT&CK mapping for a given relationship type."""
        return MITRE_TECHNIQUES.get(relationship)

    @staticmethod
    def map_attack_path(graph, path: List[str]) -> List[Dict]:
        """
        Maps each hop in an attack path to its MITRE ATT&CK technique.

        Returns a list of dicts with source, target, relationship, and MITRE data.
        """
        mappings = []
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            edge_data = graph.edges.get((u, v), {})
            rel = edge_data.get("relationship", "unknown")
            technique = MITRE_TECHNIQUES.get(rel, {
                "id": "N/A",
                "name": "Unmapped Relationship",
                "tactic": "Unknown",
                "description": f"Relationship '{rel}' has no ATT&CK mapping.",
                "mitigations": [],
            })
            mappings.append({
                "hop": i + 1,
                "source": u,
                "target": v,
                "relationship": rel,
                "mitre_id": technique.get("id", "N/A"),
                "mitre_name": technique.get("name", "Unknown"),
                "tactic": technique.get("tactic", "Unknown"),
                "description": technique.get("description", ""),
                "mitigations": technique.get("mitigations", []),
            })
        return mappings

    @staticmethod
    def get_all_tactics(mappings: List[Dict]) -> List[str]:
        """Returns unique MITRE tactics present in the attack path."""
        return list(dict.fromkeys(m["tactic"] for m in mappings))

    @staticmethod
    def generate_remediation_plan(mappings: List[Dict]) -> List[Tuple[str, List[str]]]:
        """
        Generates a prioritised remediation plan from the MITRE mappings.
        Returns list of (action_title, [specific_steps]).
        """
        all_mitigations = []
        seen = set()
        for m in mappings:
            for mitigation in m.get("mitigations", []):
                if mitigation not in seen:
                    seen.add(mitigation)
                    all_mitigations.append(
                        (f"[{m['mitre_id']}] {m['tactic']}", mitigation)
                    )
        return all_mitigations

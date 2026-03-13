# 🚀 KubeRunner: Master Project Documentation & Architecture Bluepaper
**Version:** 3.0 (Enterprise Edition Draft) | **Author:** Hack2Future Submission Team
**Tagline:** *See Your Cluster Exactly Like An Attacker Does.*

---

## 📖 0. Abstract & The Paradigm Shift

**The Fundamental Flaw in Cloud-Native Security:**
Traditional security tools (like Trivy, Falco, or Checkov) suffer from "Myopic Context Syndrome." They scan a Kubernetes cluster as a flat spreadsheet of isolated resources. A misconfigured Pod or an overly permissive Role is flagged individually, lacking the architectural context to determine if it actually matters. 

But attackers do not hack in isolated steps—they execute **Graph Traversal**. They map the cluster, exploit relationships, and chain trivial, seemingly benign permissions together to execute multi-hop lateral movements that ultimately compromise Crown Jewels (e.g., production databases, payment gateways).

**The KubeRunner Solution:**
KubeRunner completely re-frames Kubernetes security as a **Mathematical Graph Theory problem combined with Advanced Operations Research**. By modeling every entity (Pod, Secret, ServiceAccount, Database) as a vertex and every permitted action or trust relationship (`uses`, `binds`, `routes-to`, `execs`) as a directed edge weighted by its exploitability, KubeRunner mathematically proves the exact route an attacker will take.

It tells you not just *what* is vulnerable, but *how* it will be exploited, the *probabilistic timeline* of the attack succeeding, and mathematically quantifies the exact Return on Investment (ROI) of your remediation patch *before* you apply it to production.

---

## 🧱 1. Technology Stack & Architectural Core

KubeRunner V1 is engineered from first principles entirely offline, requiring zero external servers, SaaS dependencies, or AI hallucinogens—guaranteeing perfectly deterministic, explainable results.

### Core Stack (V1)
- **Backend Graph Engine:** Python 3.10+ (Type-hinted, zero native compilation required)
- **Graph Mathematics:** `networkx` 3.2 (Executing O(V+E log V) Dijkstra, BFS, DFS, Centrality)
- **Matrix Algebra:** `numpy` (Power iteration for PageRank and Eigenvector centrality matrices)
- **Data Ingestion:** `kubernetes-py` (For live cluster scraping via `.kube/config` and REST API)
- **Presentation Layer:** `Cytoscape.js` 3.28 + HTML/CSS (Client-side, WebGL-accelerated interactive UI via CDN with graceful local fallback)
- **Automated Reporting:** `fpdf2` 2.7 (Multi-page PDF generation for CISO/Compliance teams)
- **CLI Interface:** `argparse` + `colorama` (Linux-style ANSI color terminal UI)
- **Validation Engine:** `pytest` (30 deterministic unit tests guaranteeing algorithmic purity)

---

## 🧠 2. Deep Dive: Data Architecture & Network Topology

### The Graph Formulation
The heart of KubeRunner is a highly optimized `NetworkX.DiGraph` (Directed Graph).
- **Nodes (Vertices):** Represent K8s entities (`Pod`, `ServiceAccount`, `ClusterRole`, `Role`, `Secret`, `ConfigMap`, `Database`, `Service`, `User`, `Internet`).
    - *Metadata Attributes:* `id`, `type`, `cve` (Common Vulnerability Enumeration), `cvss_score`, `namespace`, `is_crown_jewel`.
- **Edges (Directed Links):** Represent the structural fabric of K8s RBAC and network routing topologies.
    - *Topologies include:* `routes-traffic-to`, `uses-service-account`, `bound-to`, `can-exec-on-nodes`, `can-read`, `authenticates-to`.

### The Secret Sauce: Exploitability Weights & CVSS Injection
Standard pathfinding algorithms (like simple BFS) simply count the number of "hops." This is fatally flawed in cybersecurity because hopping through a misconfigured API is much easier than hopping through a hardened firewall. 

KubeRunner revolutionizes this by using **Exploitability Weights**.
- Every edge has an inherent **base difficulty weight** (e.g., standard assumed permissions = weight `1.0`; jumping isolated namespaces via a complex exploit sequence = weight `8.0`).
- **CVSS Injection:** KubeRunner dynamically alters edge weights based on the destination node's CVEs. If a node has a highly exploitable, unpatched RCE vulnerability (CVSS 9.8), traversing to that node mathematically becomes "cheaper/easier" in the graph.

**Result:** KubeRunner's Dijkstra solver finds the path with the *lowest total mathematical weight*, simulating an attacker’s **Optimal Least Resistance Protocol (OLRP)**, completely disregarding the geometrical shortest path if it is hardened.

---

## ⚙️ 3. The 10 Core Sub-Engines (The Analyzer Suite)

KubeRunner executes a parallel gauntlet of 10 graph-theoretic algorithms per scan in sub-second time:

1.  **Dijkstra's Kill Chain Solver:** Calculates the absolute lowest-resistance path from an Entry Point (e.g., `public-internet`) to a Crown Jewel (e.g., `production-db`).
2.  **BFS Blast Radius Mapper:** From a single compromised node (e.g., a dev pod hit by a zero-day), performs Breadth-First Search to map every downstream node reachable within *N* hops to define the absolute mathematical limit of an active incident.
3.  **DFS Infinite Privilege Loop Detection:** Uses Depth-First Search to find cycles (Node A $\rightarrow$ Node B $\rightarrow$ Node A). In Kubernetes RBAC, this represents runaway permission loops enabling devastating, infinite privilege amplification.
4.  **Critical Node Identification (Chokepoint Locator):** Iteratively deletes nodes on the primary attack path, recalculating Dijkstra each time to identify the **Single Point of Failure**. Removing this specific node fractures the maximum number of attack paths cluster-wide.
5.  **Betweenness Centrality Ranking:** Identifies nodes acting as architectural bridges between isolated namespaces. High centrality means the node is a massive lateral-movement pivot point.
6.  **Trust PageRank:** Modifies Google's PageRank algorithm. Nodes heavily referenced by other powerful, high-privileged entities accumulate "Trust Reputation" and rise in rank as primary targets for credential theft.
7.  **Namespace Zero-Trust Audit:** Maps all directed edges that cross namespace boundaries (e.g., `dev` to `production`). Automatically flags undocumented cross-boundary dependencies breaching logical segmentation.
8.  **What-If Subgraph Computation (The Remediation Sandbox):** Clones the DiGraph into isolated memory, theoretically deletes a node/edge (as requested by the user), recalculates Dijkstra across the entire topology, and outputs a mathematical percentage (e.g., "Attack Surface reduced by 67%").
9.  **Attack Surface Heatmapping:** Generates risk scores normalized against the total node count and edge density to gauge topological fragility.
10. **MITRE ATT&CK Overlay Engine:** Algorithmically traces each edge type to its exact ATT&CK tactic (Lateral Movement, Privilege Escalation, Credential Access) mapping abstract math into industry-standard defensive frameworks.

---

## 🚀 4. The Advanced "Killer" UX Features

These are the operational differentiators that make KubeRunner an immediate tactical necessity for security teams.

### A. The Adversary Simulator (`simulator.py`)
KubeRunner translates dry Dijkstra matrix outputs into a terrifying, human-readable narrative, told from the perspective of an Advanced Persistent Threat (APT) actively dropping into the cluster.
- **Privilege Escalation Tracking:** Tracks the shifting context of the threat actor (e.g., from `Anonymous` $\rightarrow$ `Container Shell` $\rightarrow$ `API-Authenticated` $\rightarrow$ `Cluster-Admin`).
- **Temporal Estimation:** Converts mathematical weight sums into estimated exploitation times (e.g., "Trivial RBAC pivoting: ~10 seconds. Complex RCE payload delivery: ~2 minutes").
- **Technique Mapping:** Injects exactly *how* it's done (e.g., `T1609: Container Administration Command`, `T1078: Valid Cloud Accounts`).

### B. Security Scorecard Engine (`scorecard.py`)
Provides an instantly consumable `0-100 (A through F)` cluster grade for the CISO, weighted aggressively toward reality using a customized penalization matrix:
- **Critical Paths (-30 pts):** Severe penalty if a known path reaches a Crown Jewel.
- **CVE Exposure Density (-20 pts):** Based on aggregate CVSS concentration on exposed entry edges.
- **Structural Integrity (-30 pts):** Massive penalties for structural graph flaws (DFS cycles, cross-namespace bleeding).
- **Defense in Depth (+10 pts):** Reward points if shortest paths are long (e.g., 6+ hops) forcing attackers to make noise.
- **Topological Concentration (+10 pts):** Rewards diverse architectural topologies decreasing single points of failure.

### C. The Visualizer (`visualizer.py`)
Generates `attack_graph.html`, a self-contained, offline-capable Cytoscape.js canvas that brings the invisible abstract graph into reality.
- Real-time physics engine via CoSE (Compound Spring Embedder) for auto-organizing node clusters.
- **Red glowing paths:** To visualize the critical kill chain route.
- **Orange halos:** For the blast radius of a targeted compromised node.
- **Dashed Purple edges:** For highlighting privilege amplification cycles.
- **Click-to-inspect GUI:** To read CVSS scores and namespace metadata directly embedded in the DOM.

### D. GitOps Temporal Posture Diffing (`temporal.py`)
Exports a mathematically pure JSON snapshot of the network state (`--snapshot`).
After a new Helm release or Terraform plan applies, a second snapshot is taken. The `--diff` function performs an isomorphic sub-graph structural diff to reveal exactly what new edges and attack paths the deployment silently introduced.

---

## 🔮 5. The V2 Enterprise Blueprint (The "Goated" Vision)

This section details the highly advanced roadmap pitched for Hack2Future, detailing the transition of KubeRunner from a reactive CLI to a proactive, **Autonomous Cloud Native Application Protection Platform (CNAPP)**.

### I. eBPF Kernel-Level Runtime Fusion (The Holy Grail)
- **Concept:** Static graphs show what an attacker *can* do. eBPF shows what they *are doing limitlessly in real-time*.
- **Implementation:** Integrating a Rust-based eBPF watcher (leveraging Tetragon or Cilium) to trace network sockets, TCP handshakes, and `execve` syscalls inside containers directly at the Linux Kernel level.
- **Result:** If KubeRunner's static Dijkstra graph shows `Pod A` can attack `Database B`, and the live eBPF stream detects abnormal TCP traffic or a shell spawn on that exact vector, KubeRunner triggers a **"Graph-Proven Active Exploitation"** alert and can instantly auto-sever the pod's network interface.

### II. Bayesian EPSS Threat Modeling
- **Concept:** CVSS scores are obsolete. `9.8 Critical` means nothing if Threat Actors aren't actually using the payload in the wild.
- **Implementation:** Querying the live **Exploit Prediction Scoring System (EPSS)** stream from FIRST.org.
- **Result:** KubeRunner calculates the joint Bayesian Probability of the entire kill chain succeeding. Output: *"There is an 82.4% mathematical probability of this attack path being exploited in the next 30 days based on active global ransomware telemetry."*

### III. LLM-Agent Autonomous Remediation Loop (Generative Security)
- **Concept:** Recommending a fix is good. Automatically generating the fix and mathematically proving it works is revolutionary.
- **Implementation:** KubeRunner routes the JSON subgraph of a critical chokepoint into an LLM Agent (GPT-4o or Claude 3.5 Sonnet). The agent generates a hyper-specific least-privilege `NetworkPolicy` or `RoleBinding` patch.
- **Validation:** KubeRunner intercepts the LLM's suggested patch, feeds it into its offline "What-If" Subgraph Computation engine, and mathematically guarantees to the engineer that the AI’s generated code definitively severs the attack path without breaking core application traffic functionality. (Solving the LLM hallucination problem via mathematical verification).

### IV. Cross-Cloud Federated IAM Graphing (The Boundaryless Graph)
- **Concept:** Modern attacks traverse cloud boundaries as easily as namespaces.
- **Implementation:** Ingesting AWS IAM, GCP IAM, and Azure AD topologies via native cloud APIs and combining them into the core KubeRunner DiGraph.
- **Result:** Mapping an attack path where a hacker breaks into a K8s pod, assumes an AWS Web Identity Role via OIDC, reads a highly privileged Terraform state file in an S3 bucket, and pivots to compromise a completely unrelated Azure AKS cluster. A single uninterrupted graph from edge ingress to multi-cloud compromise.

### V. GitOps Pre-Merge CI/CD Blocking (Preventative Action)
- **Concept:** Catch attack paths *before* they are born and deployed.
- **Implementation:** A native GitHub App / GitLab Action that runs during the Pull Request phase. It takes the proposed `deployment.yaml` changes, injects them into a shadow instance of the live production KubeRunner graph, and fails the PR pipeline natively if the code change structurally shortens a Dijkstra path to any labeled Crown Jewel.

---
*KubeRunner: Built to shift cloud security from a reactive, isolated checklist into a decisive, unified mathematical absolute.*

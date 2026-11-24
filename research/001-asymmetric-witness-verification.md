# Technical Brief #001: Asymmetric Verification

**Subtitle:** Auditing NP-Hard Optimization & Agentic Outputs Without Kernel Disclosure  
**Author:** [@wyldcam](https://github.com/wyldcam) | **License:** MIT

---

## 1. The Reproducibility vs. IP Dilemma

Engineering teams building high-performance combinatorial solvers or specialized reasoning pipelines face a recurring tension:

- **Unverified claims lack credibility:** Publishing runtime tables or summary metrics alone asks reviewers to take results on faith.
- **Full kernel disclosure destroys defensibility:** Publishing proprietary source code, memory layouts, or domain heuristics surrenders core R&D advantage.

Complexity theory provides a clean architectural boundary between the two. For NP optimization problems, **synthesizing** a near-optimal witness is computationally hard and proprietary, whereas **verifying** a candidate witness is deterministic, public, and linear-time.

---

## 2. Linear-Time Witness Auditing ($O(|V| + |E|)$)

Take Minimum Weight Vertex Cover (MWVC) on an undirected weighted graph $G = (V, E, w)$ as a concrete benchmark model. Given only the public input graph and a static witness file listing a candidate subset $C \subseteq V$, any third party or automated agent can verify three properties in $O(|V| + |E|)$ time with zero access to the solver binary:

1. **Feasibility (100% Edge Coverage):**
   $$\forall (u, v) \in E, \quad u \in C \lor v \in C$$
   Any uncovered edge immediately invalidates the certificate.

2. **Exact Objective Accounting:**
   $$W(C) = \sum_{v \in C} w(v)$$
   Computed directly from the public instance weights, eliminating reporting drift or floating-point ambiguity.

3. **1-Minimality (Redundancy Audit):**
   $$\forall v \in C, \quad N(v) \not\subseteq C$$
   If every neighbor of $v$ is already in $C$, then $C \setminus \{v\}$ remains a valid cover with strictly smaller cardinality/weight, flagging unpruned residue.

4. **Cryptographic Manifest Binding:**
   Recording the canonical SHA-256 digest of each sorted witness alongside instance hashes locks an immutable timestamped audit trail.

---

## 3. Extending the Pattern to Tool-Augmented AI Agents

The same proposer/verifier split eliminates hallucination and drift in autonomous AI systems:

| Layer | Trust Level | Responsibility |
| :--- | :--- | :--- |
| **Solver / LLM Proposer** | Untrusted / Black-Box | Searches complex state spaces, proposes plans, patches, or candidate certificates |
| **Deterministic Verifier (MCP / Harness)** | Trusted / Open-Source | Enforces $O(N)$ feasibility, JSON Schema invariants, and outbound secret/path hygiene |

By keeping the **verifier** 100% open, dependency-free, and inspectable, external collaborators and automated agents can independently audit every published artifact while core synthesis engines remain air-gapped.

---

## Reference Implementations

- **MCP Stdio Verifier:** [`mcp-servers/graph_witness_mcp.py`](../mcp-servers/graph_witness_mcp.py)
- **Public 5k-130k MWVC Witness Dataset:** [`wyldcam/nspl-gpu-mwvc-witnesses`](https://github.com/wyldcam/nspl-gpu-mwvc-witnesses)

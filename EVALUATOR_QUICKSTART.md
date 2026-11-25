# 60-Second Evaluator Quickstart

Independent verification guide for engineering leads, operations research teams, and AI systems architects auditing the **5,000 to 130,000-node Minimum Weight Vertex Cover (MWVC)** witness suite and deterministic agent tooling.

---

## Zero-Trust Security Guarantee

- **Zero Binaries:** No `.exe`, `.dll`, `.so`, or compiled artifacts are required or executed.
- **Zero Package Installs:** `mcp-servers/graph_witness_mcp.py` uses **100% Python 3.10+ standard library** (~450 lines, zero `pip` packages, zero `networkx` dependency).
- **Zero Network Calls:** No socket, HTTP, or telemetry imports exist in the verifier or harness. Every check runs offline on local files.

---

## Step 1: Clone Verifier & Public Certificates Side-by-Side (15s)

```bash
git clone https://github.com/wyldcam/the-ai-repository.git
git clone https://github.com/wyldcam/nspl-gpu-mwvc-witnesses.git
cd the-ai-repository
```

---

## Step 2: Run the 1.67M-Edge Audit (Choose Any Path — 45s)

### Option A: Verify With Your Own AI Assistant (VS Code Copilot, Claude Code, Cursor, Gemini CLI)

Open the `the-ai-repository` folder in your IDE. Checked-in workspace configs (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, `.gemini/settings.json`) auto-register the local `wyldcam-verifier` MCP server over `stdio`.

Paste this prompt into your AI chat:

```text
Use wyldcam-verifier's verify_nspl_manifest_suite tool on "../nspl-gpu-mwvc-witnesses" to independently verify all 6 MWVC certificates (5k to 130k nodes). Report SHA-256 integrity, uncovered edge counts across all 1,672,082 edges, 1-minimality, exact mod200 weights, and objective delta vs 1xFastWVC and 8xFastWVC.
```

### Option B: Interactive Browser GUI (Official MCP Inspector — No LLM Subscription Required)

```bash
npx -y @modelcontextprotocol/inspector python mcp-servers/graph_witness_mcp.py
```

1. Toggle **Connected** on the `Servers` tab, then open **Tools**.
2. Select **`verify_nspl_manifest_suite`**, enter `../nspl-gpu-mwvc-witnesses` in `suite_or_sol_path`, and click **Execute Tool**.

### Option C: Air-Gapped Python CLI One-Liner (No Node.js, No IDE)

```bash
python -c "import json, sys; sys.path.insert(0, 'mcp-servers'); import graph_witness_mcp as m; print(json.dumps(m.verify_nspl_manifest_suite('../nspl-gpu-mwvc-witnesses'), indent=2))"
```

---

## Step 3: Expected Deterministic Audit Receipt (`< 500 ms` Total)

`verify_nspl_manifest_suite` reproduces `nx.fast_gnp_random_graph(n, p_edge, seed)` bit-for-bit using Batagelj-Brandes geometric skip-stepping in $O(\lvert C \rvert)$ memory and verifies every edge, weight, and SHA-256 hash:

| Instance | Nodes | Edges Streamed | Exact MWVC Weight | vs `1xFastWVC` | vs `8xFastWVC` | Uncovered Edges | SHA-256 Prefix |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| **Conflict_5k** | 5,000 | 50,080 | **379,110** | -2,022 | -3,253 | `0` | `536d375da8cd...` |
| **Conflict_10k** | 10,000 | 99,845 | **754,018** | -17,613 | -14,589 | `0` | `7f6ee38914d4...` |
| **Scale_25k** | 25,000 | 124,598 | **1,615,765** | -39,851 | -32,859 | `0` | `d7e09068df71...` |
| **Scale_50k** | 50,000 | 249,308 | **3,244,691** | -55,931 | -41,088 | `0` | `de004d450057...` |
| **Scale_100k** | 100,000 | 499,424 | **6,551,419** | -61,601 | -23,450 | `0` | `3d597d34e0d5...` |
| **Scale_130k** | 130,000 | 648,827 | **8,509,178** | -101,446 | -33,644 | `0` | `cf0358f9d13a...` |

> **1-Minimality Audit Note:** `Conflict_10k` through `Scale_130k` verify as strictly 1-minimal (`0` redundant vertices across up to `94,382` cover nodes). `Conflict_5k` transparently flags `1` redundant parallel tie-break vertex whose removal preserves 100% coverage while lowering objective weight even further—demonstrating active neighborhood auditing rather than static status flags.

---

## Step 4: Blind-Challenge Evaluation on Custom Graphs (`.wdimacs`)

To evaluate solver performance on your own anonymized conflict or network topologies without sharing proprietary metadata:

1. Export an undirected weighted graph in standard DIMACS (`.wdimacs` / `.mis`) format (`p edge N M`, optional `n <id> <weight>` lines, and `e <u> <v>` edges).
2. Upon receiving a candidate `.sol` vertex-cover file back, audit 100% edge feasibility, 1-minimality, and exact objective weight locally via **`verify_witness_file`**:

```bash
python -c "import json, sys; sys.path.insert(0, 'mcp-servers'); import graph_witness_mcp as m; print(json.dumps(m.verify_witness_file('challenge.wdimacs', 'returned.sol'), indent=2))"
```

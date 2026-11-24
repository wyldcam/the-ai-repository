# The AI Repository

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![MCP: v0.2.0 Ready](https://img.shields.io/badge/MCP-Multi--Client_Auto--Discovery-8b5cf6.svg)](./mcp-servers)
[![Lineage: Est. 2011](https://img.shields.io/badge/Archive-2011_tAIR_(GPLv3)-6e7681.svg)](https://github.com/wyldcam/the-ai-repository/tree/legacy/2011-tair)
[![Focus: Agentic AI & Verification](https://img.shields.io/badge/Focus-Agentic_AI_%26_Verification-10b981.svg)](https://github.com/wyldcam)

Open-source hub for deterministic agent harnesses, zero-dependency Model Context Protocol (MCP) verification servers, zero-drift prompt contracts, and technical architecture briefs by [@wyldcam](https://github.com/wyldcam).

---

## Featured Artifacts

| Path | Type | Description |
| :--- | :--- | :--- |
| [`mcp-servers/graph_witness_mcp.py`](./mcp-servers/graph_witness_mcp.py) | **Python MCP Server (`v0.2.0`)** | Stdlib-only `stdio` MCP server with disk-streaming 5k-130k witness verification (`verify_witness_file`), inline graph checks, JSON contract validation, and zero-leak scanning |
| [`.mcp.json`](./.mcp.json) / [`.vscode/`](./.vscode/mcp.json) / [`.cursor/`](./.cursor/mcp.json) / [`.gemini/`](./.gemini/settings.json) | **Auto-Discovery Configs** | Turnkey workspace MCP configs for Claude Code, VS Code Copilot, Cursor, and Gemini CLI right on `git clone` |
| [`prompts/zero-drift-pack/`](./prompts/zero-drift-pack) | **Prompt + Schema Pack** | State-pinned execution contract and strict JSON Schema (Draft 2020-12) preventing multi-turn LLM constraint drift |
| [`agents/deterministic_harness.py`](./agents/deterministic_harness.py) | **Python Harness** | Local-first wrapper enforcing schema invariants, bounded diagnostic retries, and outbound payload hygiene |
| [`research/001-asymmetric-witness-verification.md`](./research/001-asymmetric-witness-verification.md) | **Tech Brief #001** | *Asymmetric Verification*: auditing NP-hard optimization certificates and agent outputs in $O(\|V\|+\|E\|)$ time without kernel disclosure |

---

## Quick Start & "Verify With Your Own AI"

Zero external packages required (Python 3.10+ standard library). Clone and open in **VS Code Copilot**, **Claude Code**, **Cursor**, or **Gemini CLI**—`wyldcam-verifier` auto-registers via the checked-in workspace configs:

```bash
# Run built-in deterministic & 10k-node streaming scale self-tests
python mcp-servers/graph_witness_mcp.py --selftest
python agents/deterministic_harness.py --selftest

# Inspect tools interactively in your browser (no paid LLM subscription required)
npx -y @modelcontextprotocol/inspector python mcp-servers/graph_witness_mcp.py

# Pull just the Zero-Drift Prompt Pack into any project
npx degit wyldcam/the-ai-repository/prompts/zero-drift-pack ./prompts/zero-drift-pack
```

---

## Connected Ecosystem

| Repository | Focus |
| :--- | :--- |
| [**nspl-gpu-mwvc-witnesses**](https://github.com/wyldcam/nspl-gpu-mwvc-witnesses) | Public 5k-130k node Minimum Weight Vertex Cover (`.sol`) witness certificates, SHA-256 manifests, and independent verifier |
| [**octotools-wyldvariant**](https://github.com/wyldcam/octotools-wyldvariant) | Extensible agentic framework for tool-augmented multi-step reasoning |
| [**storm-wyldvariant**](https://github.com/wyldcam/storm-wyldvariant) | LLM-driven deep research curation and grounded report synthesis |
| [**sentinel-project-wyldvariant**](https://github.com/wyldcam/sentinel-project-wyldvariant) | Critical-infrastructure cyber defense and security automation |

---

## Repository Lineage (2011 -> 2026)

This repository originated in **January 2011** on Google Code as **tAIR (*The App Inventor Repository*)** - an early Android 2.x community companion app. To preserve open-source history cleanly:

- **2011 Snapshot:** Preserved intact on branch [`legacy/2011-tair`](https://github.com/wyldcam/the-ai-repository/tree/legacy/2011-tair) and tag [`v2.1-tair-2011`](https://github.com/wyldcam/the-ai-repository/releases/tag/v2.1-tair-2011) under its original **GPLv3** license.
- **Modern `main` Branch:** Initialized from a clean root commit under the **MIT License** for modern AI engineering.

---

## Live Production Case Study: Sub-Second GPU Conflict-Graph Verification (5k – 130k Nodes)

Our MCP witness-verification architecture (mcp-servers/graph_witness_mcp.py) is battle-tested in production against **NSPL-GPU-OPT**, a closed-source CUDA 13.0 (sm_89) / C++20 solver for large-scale **Minimum Weight Vertex Cover (MWVC)**, **Maximum Weight Independent Set (MWIS)**, and **MILP conflict-graph primal heuristics**.

Rather than trusting unverified heuristic claims, every benchmark run emits an independent NP witness certificate (.sol vertex cover + SHA-256 manifest) audited in (V + E)$ time:

* **Full Cryptographic Witness Suite & Auditor:** [wyldcam/nspl-gpu-mwvc-witnesses](https://github.com/wyldcam/nspl-gpu-mwvc-witnesses)
* **Verified Hardware Highlights (NVIDIA L4 sm_89):**
  * **10,000 nodes / 99,845 edges (101.5 ms):** Solves to 754,018 (-14,589 vs. 8-thread FastWVC) while both HiGHS MILP (1.84s) and 8-worker OR-Tools CP-SAT (1.11s) fail to find a feasible solution.
  * **50,000 nodes / 249,308 edges (258.0 ms):** Saves **-55,931** weight units vs. FastWVC (-41,088 vs. 8-thread FastWVC).
  * **130,000 nodes / 648,827 edges (526.5 ms):** Saves **-101,446** weight units vs. FastWVC (-33,644 vs. 8-thread FastWVC).

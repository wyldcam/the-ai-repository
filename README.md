# The AI Repository

[![Verification & Hygiene CI](https://github.com/wyldcam/the-ai-repository/actions/workflows/ci.yml/badge.svg)](https://github.com/wyldcam/the-ai-repository/actions/workflows/ci.yml)
[![Live Docs Portal](https://img.shields.io/badge/Docs-wyldcam.github.io-2563eb.svg)](https://wyldcam.github.io/the-ai-repository/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![MCP: v0.3.1 Ready](https://img.shields.io/badge/MCP-Multi--Client_Auto--Discovery-8b5cf6.svg)](./mcp-servers)
[![Lineage: Est. 2011](https://img.shields.io/badge/Archive-2011_tAIR_(GPLv3)-6e7681.svg)](https://github.com/wyldcam/the-ai-repository/tree/legacy/2011-tair)

Open-source hub for deterministic agent harnesses, zero-dependency Model Context Protocol (MCP) verification servers, 5k-130k NP witness auditors, zero-drift prompt contracts, and technical architecture briefs by [@wyldcam](https://github.com/wyldcam).

> **Evaluating the 5k-130k MWVC Benchmarks?** Start with the **[60-Second Evaluator Quickstart](./EVALUATOR_QUICKSTART.md)** or browse the **[Live Documentation Portal](https://wyldcam.github.io/the-ai-repository/)**.

---

## Featured Artifacts

| Path | Type | Description |
| :--- | :--- | :--- |
| [`EVALUATOR_QUICKSTART.md`](./EVALUATOR_QUICKSTART.md) | **60s Audit Guide** | Step-by-step verification via VS Code Copilot, Claude Code, Cursor, Gemini CLI, MCP Inspector, or air-gapped Python CLI |
| [`mcp-servers/graph_witness_mcp.py`](./mcp-servers/graph_witness_mcp.py) | **Python MCP Server (`v0.3.1`)** | Stdlib-only `stdio` MCP server auditing 5k-130k MWVC witness suites (`1.67M` edges in `< 0.5s`), `.wdimacs` challenges, JSON schemas, and zero-leak hygiene |
| [`.mcp.json`](./.mcp.json) / [`.vscode/`](./.vscode/mcp.json) / [`.cursor/`](./.cursor/mcp.json) / [`.gemini/`](./.gemini/settings.json) | **Auto-Discovery Configs** | Turnkey workspace MCP configs for Claude Code, VS Code Copilot, Cursor, and Gemini CLI right on `git clone` |
| [`scripts/repo_hygiene_gate.py`](./scripts/repo_hygiene_gate.py) | **CI & Pre-Commit Gate** | Repo-wide zero-leak scanner, binary/extension blocker, MCP config portability validator, and live `stdio` JSON-RPC handshake test |
| [`prompts/zero-drift-pack/`](./prompts/zero-drift-pack) | **Prompt + Schema Pack** | State-pinned execution contract and strict JSON Schema (Draft 2020-12) preventing multi-turn LLM constraint drift |
| [`agents/deterministic_harness.py`](./agents/deterministic_harness.py) | **Python Harness** | Local-first wrapper enforcing schema invariants, bounded diagnostic retries, and outbound payload hygiene |
| [`research/001-asymmetric-witness-verification.md`](./research/001-asymmetric-witness-verification.md) | **Tech Brief #001** | *Asymmetric Verification*: auditing NP-hard optimization certificates and agent outputs in $O(\lvert V \rvert + \lvert E \rvert)$ time without kernel disclosure |
| [`research/VertexCoverSoundness.lean`](./research/VertexCoverSoundness.lean) | **Lean 4 Proof** | Formal post-solve soundness verification of vertex cover feasibility predicates |

---

## Verified 5k-130k MWVC Witness Suite (`< 500 ms` Pure-Stdlib Audit)

All six public certificates in [`wyldcam/nspl-gpu-mwvc-witnesses`](https://github.com/wyldcam/nspl-gpu-mwvc-witnesses) stream and verify locally in pure Python standard library with `0` uncovered edges across `1,672,082` edges:

| Instance | Nodes | Edges Verified | Exact MWVC Weight | Delta vs `1xFastWVC` | Delta vs `8xFastWVC` | Audit Status |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| **Conflict_5k** | 5,000 | 50,080 | **379,110** | -2,022 | -3,253 | `PASS (SHA + 100% Cover)` |
| **Conflict_10k** | 10,000 | 99,845 | **754,018** | -17,613 | -14,589 | `PASS (SHA + 1-Minimal)` |
| **Scale_25k** | 25,000 | 124,598 | **1,615,765** | -39,851 | -32,859 | `PASS (SHA + 1-Minimal)` |
| **Scale_50k** | 50,000 | 249,308 | **3,244,691** | -55,931 | -41,088 | `PASS (SHA + 1-Minimal)` |
| **Scale_100k** | 100,000 | 499,424 | **6,551,419** | -61,601 | -23,450 | `PASS (SHA + 1-Minimal)` |
| **Scale_130k** | 130,000 | 648,827 | **8,509,178** | -101,446 | -33,644 | `PASS (SHA + 1-Minimal)` |

---

## Quick Start & Self-Tests

Zero external packages required (Python 3.10+ standard library):

```bash
# Run full repo hygiene gate, MCP stdio handshake, & deterministic self-tests
python scripts/repo_hygiene_gate.py
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
| [**nspl-gpu-mwvc-witnesses**](https://github.com/wyldcam/nspl-gpu-mwvc-witnesses) | Public 5k-130k node Minimum Weight Vertex Cover (`.sol`) witness certificates, SHA-256 manifests, and independent linear-time verifier |
| [**@wyldcam**](https://github.com/wyldcam) | Independent R&D profile, formal verification benchmarks, and systems architecture overview |

---

## Repository Lineage (2011 -> 2026)

This repository originated in **January 2011** on Google Code as **tAIR (*The App Inventor Repository*)** - an early Android 2.x community companion app. To preserve open-source history cleanly:

- **2011 Snapshot:** Preserved intact on branch [`legacy/2011-tair`](https://github.com/wyldcam/the-ai-repository/tree/legacy/2011-tair) and tag [`v2.1-tair-2011`](https://github.com/wyldcam/the-ai-repository/releases/tag/v2.1-tair-2011) under its original **GPLv3** license.
- **Modern `main` Branch:** Initialized from a clean root commit under the **MIT License** for modern AI engineering.

# The AI Repository

[![Verification & Hygiene CI](https://github.com/wyldcam/the-ai-repository/actions/workflows/ci.yml/badge.svg)](https://github.com/wyldcam/the-ai-repository/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![MCP: v0.3.0 Ready](https://img.shields.io/badge/MCP-Multi--Client_Auto--Discovery-8b5cf6.svg)](./mcp-servers)
[![Lineage: Est. 2011](https://img.shields.io/badge/Archive-2011_tAIR_(GPLv3)-6e7681.svg)](https://github.com/wyldcam/the-ai-repository/tree/legacy/2011-tair)

Open-source hub for deterministic agent harnesses, zero-dependency Model Context Protocol (MCP) verification servers, zero-drift prompt contracts, and technical architecture briefs by [@wyldcam](https://github.com/wyldcam).

---

## Featured Artifacts

| Path | Type | Description |
| :--- | :--- | :--- |
| [`mcp-servers/graph_witness_mcp.py`](./mcp-servers/graph_witness_mcp.py) | **Python MCP Server (`v0.3.0`)** | Stdlib-only `stdio` MCP server auditing seed-generated 5k-130k MWVC witness suites (`verify_nspl_manifest_suite`), `.wdimacs`/DIMACS disk-streaming graphs, JSON schemas, and zero-leak hygiene |
| [`.mcp.json`](./.mcp.json) / [`.vscode/`](./.vscode/mcp.json) / [`.cursor/`](./.cursor/mcp.json) / [`.gemini/`](./.gemini/settings.json) | **Auto-Discovery Configs** | Turnkey workspace MCP configs for Claude Code, VS Code Copilot, Cursor, and Gemini CLI right on `git clone` |
| [`scripts/repo_hygiene_gate.py`](./scripts/repo_hygiene_gate.py) | **CI & Pre-Commit Gate** | Repo-wide zero-leak scanner, binary/extension blocker, MCP config portability validator, and live `stdio` JSON-RPC handshake test |
| [`prompts/zero-drift-pack/`](./prompts/zero-drift-pack) | **Prompt + Schema Pack** | State-pinned execution contract and strict JSON Schema (Draft 2020-12) preventing multi-turn LLM constraint drift |
| [`agents/deterministic_harness.py`](./agents/deterministic_harness.py) | **Python Harness** | Local-first wrapper enforcing schema invariants, bounded diagnostic retries, and outbound payload hygiene |
| [`research/001-asymmetric-witness-verification.md`](./research/001-asymmetric-witness-verification.md) | **Tech Brief #001** | *Asymmetric Verification*: auditing NP-hard optimization certificates and agent outputs in $O(\|V\|+\|E\|)$ time without kernel disclosure |

---

## Quick Start & "Verify With Your Own AI"

Zero external packages required (Python 3.10+ standard library—not even `networkx` needed). Clone and open in **VS Code Copilot**, **Claude Code**, **Cursor**, or **Gemini CLI**:

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

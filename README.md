# The AI Repository

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Lineage: Est. 2011](https://img.shields.io/badge/Archive-2011_tAIR_(GPLv3)-6e7681.svg)](https://github.com/wyldcam/the-ai-repository/tree/legacy/2011-tair)
[![Focus: Agentic AI & Verification](https://img.shields.io/badge/Focus-Agentic_AI_%26_Verification-10b981.svg)](https://github.com/wyldcam)

Open-source hub for deterministic agent harnesses, zero-dependency Model Context Protocol (MCP) verification servers, zero-drift prompt contracts, and technical architecture briefs by [@wyldcam](https://github.com/wyldcam).

---

## Featured Artifacts

| Path | Type | Description |
| :--- | :--- | :--- |
| [`mcp-servers/graph_witness_mcp.py`](./mcp-servers/graph_witness_mcp.py) | **Python MCP Server** | Stdlib-only `stdio` MCP server exposing polynomial-time graph witness verification, JSON contract checks, and outbound secret/path leak scanning |
| [`prompts/zero-drift-pack/`](./prompts/zero-drift-pack) | **Prompt + Schema Pack** | State-pinned execution contract and strict JSON Schema (Draft 2020-12) preventing multi-turn LLM constraint drift |
| [`agents/deterministic_harness.py`](./agents/deterministic_harness.py) | **Python Harness** | Local-first wrapper enforcing schema invariants, bounded diagnostic retries, and outbound payload hygiene |
| [`research/001-asymmetric-witness-verification.md`](./research/001-asymmetric-witness-verification.md) | **Tech Brief #001** | *Asymmetric Verification*: auditing NP-hard optimization certificates and agent outputs in $O(\|V\|+\|E\|)$ time without kernel disclosure |

---

## Quick Start & Self-Tests

Zero external packages required (Python 3.10+ standard library):

```bash
# Run built-in verification & zero-leak self-tests
python mcp-servers/graph_witness_mcp.py --selftest
python agents/deterministic_harness.py --selftest

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

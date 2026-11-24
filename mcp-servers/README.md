# MCP Servers (`v0.2.0`)

Zero-bloat, local-first **Model Context Protocol (MCP)** verification server written purely against the Python 3.10+ standard library (`stdio` JSON-RPC 2.0 transport - zero `pip` dependencies, zero network calls).

## Zero-Setup Multi-Client Auto-Discovery

Cloning this repository automatically configures `wyldcam-verifier` across major AI coding environments:

| Client / IDE | Checked-In Config | Notes |
| :--- | :--- | :--- |
| **Claude Code & VS Code Copilot** | [`.mcp.json`](../.mcp.json) | Portable workspace MCP format |
| **VS Code (Editor MCP)** | [`.vscode/mcp.json`](../.vscode/mcp.json) | Uses VS Code `servers` root key |
| **Cursor** | [`.cursor/mcp.json`](../.cursor/mcp.json) | Auto-detected when opening repo folder |
| **Gemini CLI** | [`.gemini/settings.json`](../.gemini/settings.json) | Run `gemini trust` once in repo root if prompted |

*(Note for macOS/Linux users without a `python` symlink on `PATH`: replace `"python"` with `"python3"` in your preferred config.)*

---

## Exposed Tools in `graph_witness_mcp.py`

1. **`verify_witness_file`** *(New in `v0.2.0` - 5k to 130k+ Scale)*
   Streams large graph benchmarks (DIMACS `.mis`/`.col`/`.clq`, PACE `.gr`, MatrixMarket `.mtx`, JSON, or plain edge lists) and `.sol`/`.vc`/JSON witness files directly from disk in single-pass $O(|V| + |E|)$ time and $O(|C|)$ RAM—bypassing LLM context-window limits. Emits coverage status, exact total weight, 1-minimality check, elapsed milliseconds, raw file SHA-256 digests, and sanitized basenames.
2. **`verify_mvc_witness`** - Inline JSON graph/witness verifier for small test instances and unit checks.
3. **`validate_structured_output`** - Validates candidate agent JSON payloads against required keys, code-fence drift, and forbidden tokens.
4. **`scan_zero_leak`** - Scans outbound diffs, prompts, or reports for local workstation paths, API keys, and `.env` secrets.

### Verify Locally

```bash
python mcp-servers/graph_witness_mcp.py --selftest
```

### Example AI Prompt for 5k-130k Witness Audits

```text
Use wyldcam-verifier's verify_witness_file tool to audit graph_path="../nspl-gpu-mwvc-witnesses/instances/Scale_130k.mis" against witness_path="../nspl-gpu-mwvc-witnesses/witnesses/Scale_130k.sol" and report edge coverage, 1-minimality, total weight, and SHA-256 digests.
```

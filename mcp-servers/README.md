# MCP Servers

Zero-bloat, local-first **Model Context Protocol (MCP)** servers written against the Python 3.10+ standard library (`stdio` JSON-RPC 2.0 transport - no virtual environment or third-party SDK install required).

## `graph_witness_mcp.py`

Exposes three deterministic verification tools to Claude Code, Claude Desktop, Cursor, or any MCP host:

1. **`verify_mvc_witness`** - Independently verifies in $O(|V| + |E|)$ time whether a candidate vertex cover covers 100% of graph edges, computes exact total weight, checks 1-minimality (flags redundant vertices whose entire neighborhood is already covered), and returns a canonical SHA-256 witness digest.
2. **`validate_structured_output`** - Validates candidate agent JSON payloads against required keys and forbidden drift substrings.
3. **`scan_zero_leak`** - Audits outbound code, diffs, or prompts for accidental workstation paths (`C:\Users\...`, `/home/...`), API tokens, and private key headers before publication.

### Verify Locally

```bash
python mcp-servers/graph_witness_mcp.py --selftest
```

### Register in `.mcp.json` (Claude Code / Cursor)

```json
{
  "mcpServers": {
    "wyldcam-verifier": {
      "command": "python",
      "args": ["mcp-servers/graph_witness_mcp.py"]
    }
  }
}
```

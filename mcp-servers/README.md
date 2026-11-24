# MCP Servers (`v0.3.0`)

Zero-bloat, local-first **Model Context Protocol (MCP)** verification server written purely against the Python 3.10+ standard library (`stdio` JSON-RPC 2.0 transport - zero `pip` packages, zero `networkx` dependency, zero network calls).

## Exposed Tools in `graph_witness_mcp.py`

1. **`verify_nspl_manifest_suite`** *(New in `v0.3.0` - Seed-Streamed 5k to 130k Suite Auditor)*
   Reproduces `nx.fast_gnp_random_graph(n, p_edge, seed)` bit-for-bit in pure Python standard library (`random.Random` + Batagelj-Brandes skip-stepping) and streams all 6 public certificates (`Conflict_5k` through `Scale_130k`, 1.67M edges total) in $O(|C|)$ RAM. Verifies SHA-256 integrity, 100% edge feasibility, 1-minimality, exact `mod200` MWVC weight, and objective savings against `1xFastWVC` and `8xFastWVC`. Accepts a repo folder path, `witness_manifest.json`, or any single `.sol` file path.
2. **`verify_witness_file`** - Disk-streaming $O(|V|+|E|)$ verifier for custom `.wdimacs` blind challenges, DIMACS `.mis`/`.col`, PACE `.gr`, MatrixMarket `.mtx`, `.gz`, or JSON files (also auto-routes `witness_manifest.json` + `.sol` pairs).
3. **`verify_mvc_witness`** - Inline JSON graph/witness verifier for small unit instances.
4. **`validate_structured_output`** - Validates candidate agent JSON payloads against required keys, code-fence drift, and forbidden tokens.
5. **`scan_zero_leak`** - Scans outbound diffs, prompts, or reports for local workstation paths, API keys, and `.env` secrets.

### Example AI Prompt (Clone Both Public Repos Side-by-Side)

```text
Use wyldcam-verifier's verify_nspl_manifest_suite tool on "../nspl-gpu-mwvc-witnesses" to independently verify all 6 MWVC certificates (5k to 130k nodes) and summarize SHA-256 status, uncovered edges, and weight delta vs 8xFastWVC.
```

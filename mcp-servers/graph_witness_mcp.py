#!/usr/bin/env python3
'''
Zero-dependency Model Context Protocol (MCP) stdio server (JSON-RPC 2.0) - v0.2.1.
Provides deterministic verification tools:
  1. verify_witness_file: Streaming O(|V| + |E|) disk verifier for 5k-130k+ graph witnesses (.gz & JSON supported)
  2. verify_mvc_witness: Inline O(|V| + |E|) graph vertex-cover & 1-minimality verifier
  3. validate_structured_output: Strict JSON key & drift-token validator
  4. scan_zero_leak: Outbound path, token, and key hygiene scanner
'''

from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, TextIO

FENCE = chr(96) * 3

LEAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("windows_user_path", re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9_][^\s,;\x60\"']*", re.IGNORECASE)),
    ("unix_home_path", re.compile(r"/(?:home|Users)/[A-Za-z0-9_][A-Za-z0-9_.-]*")),
    ("api_token", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16})\b")),
    ("private_key_header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("dotenv_secret", re.compile(r"(?m)^[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY)\s*=\s*\S+")),
]

WITNESS_JSON_KEYS = (
    "cover",
    "vertices",
    "witness",
    "solution",
    "cover_vertices",
    "selected_vertices",
    "vertex_cover",
    "nodes",
)

TOOLS: list[dict[str, Any]] = [
    {
        "name": "verify_witness_file",
        "description": "Stream a 5k-130k+ graph file (DIMACS, PACE .gr, MatrixMarket .mtx, edge list, JSON, or .gz) and a witness file (.sol, .vc, .txt, or JSON) from disk in O(|V|+|E|) time without loading edges into LLM context. Verifies 100% edge coverage, exact weight, 1-minimality, and SHA-256 file/witness digests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "graph_path": {
                    "type": "string",
                    "description": "Local path to the benchmark graph file (plain or .gz).",
                },
                "witness_path": {
                    "type": "string",
                    "description": "Local path to the candidate vertex-cover witness file (.sol, .vc, .txt, .json).",
                },
                "weights_path": {
                    "type": "string",
                    "description": "Optional path to a separate vertex-weights file if weights are not embedded in graph_path.",
                },
            },
            "required": ["graph_path", "witness_path"],
        },
    },
    {
        "name": "verify_mvc_witness",
        "description": "Verify inline in O(|V|+|E|) time that a candidate vertex list is a valid vertex cover, compute total weight, check 1-minimality, and emit a SHA-256 witness digest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "edges": {
                    "type": "array",
                    "description": "List of undirected [u, v] integer vertex pairs.",
                    "items": {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2},
                },
                "cover": {
                    "type": "array",
                    "description": "Candidate vertex cover as a list of integer vertex IDs.",
                    "items": {"type": "integer"},
                },
                "weights": {
                    "type": "object",
                    "description": "Optional map of stringified vertex ID to numeric weight (defaults to unit weight 1).",
                },
            },
            "required": ["edges", "cover"],
        },
    },
    {
        "name": "validate_structured_output",
        "description": "Validate that a string is strict JSON (no markdown wrapper drift), contains all required keys, and excludes forbidden substrings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload_json": {"type": "string"},
                "required_keys": {"type": "array", "items": {"type": "string"}},
                "forbidden_substrings": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["payload_json", "required_keys"],
        },
    },
    {
        "name": "scan_zero_leak",
        "description": "Scan outbound text, prompts, or diffs for accidental local user paths, API tokens, .env secrets, or private key headers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Content to audit before commit or external dispatch."}
            },
            "required": ["text"],
        },
    },
]


def _open_text_auto(path: Path) -> TextIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _is_json_path(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".json") or name.endswith(".json.gz")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_witness_set(witness_file: Path) -> set[int]:
    if _is_json_path(witness_file):
        with _open_text_auto(witness_file) as fh:
            raw = json.load(fh)
        if isinstance(raw, list):
            return {int(v) for v in raw}
        if isinstance(raw, dict):
            for key in WITNESS_JSON_KEYS:
                if key in raw and isinstance(raw[key], list):
                    return {int(v) for v in raw[key]}
        raise ValueError(f"JSON witness must be an array or an object containing one of {WITNESS_JSON_KEYS}.")

    cover_set: set[int] = set()
    with _open_text_auto(witness_file) as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line == "c" or line.startswith(("c ", "c\t", "#", "%", "//", "s ", "o ", "w ")):
                continue
            if line.startswith(("v ", "v\t")):
                tokens = re.split(r"[\s,]+", line[2:].strip())
            else:
                tokens = re.split(r"[\s,]+", line)
            for tok in tokens:
                if tok:
                    cover_set.add(int(tok))
    return cover_set


def _load_external_weights(weights_file: Path, cover_set: set[int], index_base: int = 1) -> dict[int, float]:
    if _is_json_path(weights_file):
        with _open_text_auto(weights_file) as fh:
            raw = json.load(fh)
        if isinstance(raw, dict):
            return {int(k): float(v) for k, v in raw.items() if int(k) in cover_set}
        if isinstance(raw, list):
            return {idx: float(w) for idx, w in enumerate(raw, start=index_base) if idx in cover_set}
        raise ValueError("JSON weights file must be an object or array.")

    weights: dict[int, float] = {}
    auto_index = index_base
    with _open_text_auto(weights_file) as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line == "c" or line.startswith(("c ", "c\t", "#", "%", "//", "p ")):
                continue
            parts = re.split(r"[\s,]+", line)
            if parts[0] in ("n", "v", "w") and len(parts) >= 3:
                vid = int(parts[1])
                if vid in cover_set:
                    weights[vid] = float(parts[2])
            elif len(parts) >= 2:
                vid = int(parts[0])
                if vid in cover_set:
                    weights[vid] = float(parts[1])
            elif len(parts) == 1:
                if auto_index in cover_set:
                    weights[auto_index] = float(parts[0])
                auto_index += 1
    return weights


def verify_witness_file(
    graph_path: str,
    witness_path: str,
    weights_path: str | None = None,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    g_file = Path(graph_path).expanduser().resolve()
    w_file = Path(witness_path).expanduser().resolve()

    if not g_file.is_file():
        raise FileNotFoundError(f"Graph file not found: {Path(graph_path).name}")
    if not w_file.is_file():
        raise FileNotFoundError(f"Witness file not found: {Path(witness_path).name}")

    cover_set = _load_witness_set(w_file)
    sorted_cover = sorted(cover_set)

    cover_weights: dict[int, float] = {}
    edge_count = 0
    uncovered_count = 0
    uncovered_sample: list[list[int]] = []
    essential_cover_nodes: set[int] = set()
    declared_vertices: int | None = None
    declared_edges: int | None = None
    max_vertex_seen = 0
    min_vertex_seen: int | None = None

    if _is_json_path(g_file):
        with _open_text_auto(g_file) as fh:
            g_data = json.load(fh)
        raw_edges = g_data.get("edges") or []
        for pair in raw_edges:
            u, v = int(pair[0]), int(pair[1])
            if u == v:
                continue
            edge_count += 1
            hi = u if u > v else v
            lo = u if u < v else v
            if hi > max_vertex_seen:
                max_vertex_seen = hi
            if min_vertex_seen is None or lo < min_vertex_seen:
                min_vertex_seen = lo
            u_in = u in cover_set
            v_in = v in cover_set
            if not u_in and not v_in:
                uncovered_count += 1
                if len(uncovered_sample) < 5:
                    uncovered_sample.append([u, v])
            else:
                if u_in and not v_in:
                    essential_cover_nodes.add(u)
                if v_in and not u_in:
                    essential_cover_nodes.add(v)

        raw_weights = g_data.get("weights")
        if isinstance(raw_weights, dict):
            for k, val in raw_weights.items():
                vid = int(k)
                if vid in cover_set:
                    cover_weights[vid] = float(val)
        elif isinstance(raw_weights, list):
            base = 0 if min_vertex_seen == 0 else 1
            for idx, val in enumerate(raw_weights, start=base):
                if idx in cover_set:
                    cover_weights[idx] = float(val)
    else:
        expect_mm_dims = False
        with _open_text_auto(g_file) as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("%%MatrixMarket"):
                    expect_mm_dims = True
                    continue
                if line == "c" or line.startswith(("c ", "c\t", "#", "%", "//")):
                    continue
                if expect_mm_dims:
                    dims = line.split()
                    if len(dims) >= 3:
                        declared_vertices = int(dims[0])
                        declared_edges = int(dims[2])
                    expect_mm_dims = False
                    continue

                first_char = line[0]
                if first_char == "p" and (len(line) == 1 or line[1].isspace()):
                    parts = line.split()
                    if len(parts) >= 4:
                        declared_vertices = int(parts[2])
                        declared_edges = int(parts[3])
                    continue

                if first_char in ("n", "v", "w") and (len(line) > 1 and line[1].isspace()):
                    parts = line.split()
                    if len(parts) >= 3:
                        vid = int(parts[1])
                        if vid in cover_set:
                            cover_weights[vid] = float(parts[2])
                    continue

                if first_char == "e" and (len(line) > 1 and line[1].isspace()):
                    parts = line.split()
                    u, v = int(parts[1]), int(parts[2])
                else:
                    parts = re.split(r"[\s,]+", line)
                    if len(parts) < 2:
                        continue
                    u, v = int(parts[0]), int(parts[1])

                if u == v:
                    continue
                edge_count += 1
                hi = u if u > v else v
                lo = u if u < v else v
                if hi > max_vertex_seen:
                    max_vertex_seen = hi
                if min_vertex_seen is None or lo < min_vertex_seen:
                    min_vertex_seen = lo

                u_in = u in cover_set
                v_in = v in cover_set
                if not u_in and not v_in:
                    uncovered_count += 1
                    if len(uncovered_sample) < 5:
                        uncovered_sample.append([u, v])
                else:
                    if u_in and not v_in:
                        essential_cover_nodes.add(u)
                    if v_in and not u_in:
                        essential_cover_nodes.add(v)

    if weights_path:
        wt_file = Path(weights_path).expanduser().resolve()
        if not wt_file.is_file():
            raise FileNotFoundError(f"Weights file not found: {Path(weights_path).name}")
        base = 0 if min_vertex_seen == 0 else 1
        cover_weights.update(_load_external_weights(wt_file, cover_set, index_base=base))

    redundant_vertices = [v for v in sorted_cover if v not in essential_cover_nodes]
    total_weight = sum(cover_weights.get(v, 1.0) for v in sorted_cover)
    canonical_digest = hashlib.sha256(",".join(str(v) for v in sorted_cover).encode("utf-8")).hexdigest()
    graph_sha256 = _sha256_file(g_file)
    witness_sha256 = _sha256_file(w_file)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "valid_cover": uncovered_count == 0,
        "graph_file": g_file.name,
        "witness_file": w_file.name,
        "declared_vertices": declared_vertices,
        "declared_edges": declared_edges,
        "max_vertex_id_observed": max_vertex_seen,
        "edge_records_verified": edge_count,
        "cover_size": len(sorted_cover),
        "weighted_vertices_matched": len(cover_weights),
        "total_weight": int(total_weight) if total_weight.is_integer() else round(total_weight, 6),
        "uncovered_edge_count": uncovered_count,
        "uncovered_edges_sample": uncovered_sample,
        "is_1_minimal": uncovered_count == 0 and len(redundant_vertices) == 0,
        "redundant_vertices_count": len(redundant_vertices),
        "redundant_vertices_sample": redundant_vertices[:10],
        "graph_file_sha256": graph_sha256,
        "witness_file_sha256": witness_sha256,
        "canonical_cover_sha256": canonical_digest,
        "elapsed_ms": elapsed_ms,
    }


def verify_mvc_witness(
    edges: list[list[int]],
    cover: list[int],
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    cover_set = set(int(v) for v in cover)
    sorted_cover = sorted(cover_set)
    weight_map = weights or {}

    adj: dict[int, set[int]] = {}
    uncovered_sample: list[list[int]] = []
    uncovered_count = 0

    for pair in edges:
        u, v = int(pair[0]), int(pair[1])
        if u == v:
            continue
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)
        if u not in cover_set and v not in cover_set:
            uncovered_count += 1
            if len(uncovered_sample) < 5:
                uncovered_sample.append([u, v])

    redundant_vertices: list[int] = []
    for v in sorted_cover:
        neighbors = adj.get(v, set())
        if neighbors and neighbors.issubset(cover_set):
            redundant_vertices.append(v)

    total_weight = sum(float(weight_map.get(str(v), 1.0)) for v in sorted_cover)
    canonical_bytes = ",".join(str(v) for v in sorted_cover).encode("utf-8")
    digest = hashlib.sha256(canonical_bytes).hexdigest()

    return {
        "valid_cover": uncovered_count == 0,
        "edge_count": len(edges),
        "cover_size": len(sorted_cover),
        "total_weight": int(total_weight) if total_weight.is_integer() else round(total_weight, 6),
        "uncovered_edge_count": uncovered_count,
        "uncovered_edges_sample": uncovered_sample,
        "is_1_minimal": uncovered_count == 0 and len(redundant_vertices) == 0,
        "redundant_vertices_count": len(redundant_vertices),
        "redundant_vertices_sample": redundant_vertices[:10],
        "witness_sha256": digest,
    }


def validate_structured_output(
    payload_json: str,
    required_keys: list[str],
    forbidden_substrings: list[str] | None = None,
) -> dict[str, Any]:
    stripped = payload_json.strip()
    errors: list[str] = []

    if stripped.startswith(FENCE):
        errors.append("Markdown code-fence wrapper detected; expected raw JSON object.")

    parsed: Any = None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        errors.append(f"JSONDecodeError at pos {exc.pos}: {exc.msg}")

    missing_keys: list[str] = []
    if isinstance(parsed, dict):
        missing_keys = [k for k in required_keys if k not in parsed]
        if missing_keys:
            errors.append(f"Missing required keys: {missing_keys}")
    elif parsed is not None:
        errors.append("Root JSON value must be an object.")

    hit_forbidden: list[str] = []
    for token in forbidden_substrings or []:
        if token and token in payload_json:
            hit_forbidden.append(token)
    if hit_forbidden:
        errors.append(f"Forbidden substrings present: {hit_forbidden}")

    return {
        "valid": len(errors) == 0,
        "missing_keys": missing_keys,
        "forbidden_hits": hit_forbidden,
        "errors": errors,
    }


def scan_zero_leak(text: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule_name, pattern in LEAK_PATTERNS:
            for match in pattern.finditer(line):
                snippet = match.group(0)
                redacted = snippet[:6] + "...[REDACTED]" if len(snippet) > 8 else "[REDACTED]"
                findings.append({"line": line_no, "rule": rule_name, "preview": redacted})
    return {
        "clean": len(findings) == 0,
        "finding_count": len(findings),
        "findings": findings,
    }


def dispatch_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "verify_witness_file":
        return verify_witness_file(
            graph_path=arguments["graph_path"],
            witness_path=arguments["witness_path"],
            weights_path=arguments.get("weights_path"),
        )
    if name == "verify_mvc_witness":
        return verify_mvc_witness(
            edges=arguments["edges"],
            cover=arguments["cover"],
            weights=arguments.get("weights"),
        )
    if name == "validate_structured_output":
        return validate_structured_output(
            payload_json=arguments["payload_json"],
            required_keys=arguments["required_keys"],
            forbidden_substrings=arguments.get("forbidden_substrings"),
        )
    if name == "scan_zero_leak":
        return scan_zero_leak(text=arguments["text"])
    raise ValueError(f"Unknown tool: {name}")


def serve_stdio() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        if req_id is None:
            continue

        if method == "initialize":
            result: Any = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "wyldcam-verification-mcp", "version": "0.2.1"},
            }
            resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
        elif method == "ping":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            try:
                tool_out = dispatch_tool(params.get("name", ""), params.get("arguments") or {})
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(tool_out, indent=2)}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Tool error: {exc}"}],
                        "isError": True,
                    },
                }
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


def run_selftest() -> None:
    cycle_edges = [[1, 2], [2, 3], [3, 4], [4, 5], [1, 5]]
    res_min = verify_mvc_witness(cycle_edges, [1, 3, 4], {"1": 2, "3": 5, "4": 3})
    assert res_min["valid_cover"] is True and res_min["is_1_minimal"] is True, res_min
    assert res_min["total_weight"] == 10, res_min

    res_red = verify_mvc_witness(cycle_edges, [1, 2, 3, 4])
    assert res_red["valid_cover"] is True and res_red["is_1_minimal"] is False, res_red
    assert res_red["redundant_vertices_count"] == 2, res_red

    res_schema = validate_structured_output('{"status":"ok","step":1}', ["status", "step"])
    assert res_schema["valid"] is True, res_schema

    sample_path = "C:" + "\\Users\\demo_account\\private_notes.txt"
    res_leak = scan_zero_leak(f"Loaded config from {sample_path}")
    assert res_leak["clean"] is False and res_leak["finding_count"] == 1, res_leak

    placeholder_doc = "Audits paths like C:" + "\\Users\\... and /home/..."
    assert scan_zero_leak(placeholder_doc)["clean"] is True

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        g_path = tmp / "synthetic_10k.mis.gz"
        w_path = tmp / "synthetic_10k.sol"

        lines = ["c Synthetic 10k MWVC streaming test", "p edge 10000 15000"]
        expected_weight = 0
        cover_ids: list[int] = []
        for v in range(1, 10001):
            wt = (v % 7) + 1
            lines.append(f"n {v} {wt}")
            if v % 2 == 1:
                cover_ids.append(v)
                expected_weight += wt

        for k in range(1, 5001):
            odd_u = 2 * k - 1
            even_v = 2 * k
            next_even = 2 * ((k % 5000) + 1)
            next_odd = next_even - 1
            lines.append(f"e {odd_u} {even_v}")
            lines.append(f"e {odd_u} {next_even}")
            lines.append(f"e {odd_u} {next_odd}")

        with gzip.open(g_path, "wt", encoding="utf-8") as gz_out:
            gz_out.write("\n".join(lines) + "\n")
        w_lines = ["c 1-minimal witness", f"s vc 10000 {len(cover_ids)}"] + [str(v) for v in cover_ids]
        w_path.write_text("\n".join(w_lines) + "\n", encoding="utf-8")

        res_stream = verify_witness_file(str(g_path), str(w_path))
        assert res_stream["valid_cover"] is True, res_stream
        assert res_stream["is_1_minimal"] is True, res_stream
        assert res_stream["cover_size"] == 5000, res_stream
        assert res_stream["edge_records_verified"] == 15000, res_stream
        assert res_stream["total_weight"] == expected_weight, res_stream
        assert res_stream["graph_file"] == "synthetic_10k.mis.gz", res_stream
        assert scan_zero_leak(json.dumps(res_stream))["clean"] is True

        bundle_path = tmp / "bundle_0idx.json"
        bundle_path.write_text(
            json.dumps({"edges": [[0, 1], [1, 2], [2, 0]], "weights": [4, 7, 9], "selected_vertices": [0, 1]}),
            encoding="utf-8",
        )
        res_bundle = verify_witness_file(str(bundle_path), str(bundle_path))
        assert res_bundle["valid_cover"] is True and res_bundle["is_1_minimal"] is True, res_bundle
        assert res_bundle["total_weight"] == 11, res_bundle

    print("[PASS] graph_witness_mcp.py (v0.2.1): all 6 deterministic, .gz streaming & JSON bundle self-tests passed.")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        run_selftest()
    else:
        serve_stdio()

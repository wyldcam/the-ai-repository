#!/usr/bin/env python3
'''
Zero-dependency Model Context Protocol (MCP) stdio server (JSON-RPC 2.0).
Provides deterministic verification tools:
  1. verify_mvc_witness: O(|V| + |E|) graph vertex-cover & 1-minimality verifier
  2. validate_structured_output: strict JSON key & drift-token validator
  3. scan_zero_leak: outbound path, token, and key hygiene scanner
'''

from __future__ import annotations

import hashlib
import json
import re
import sys
from typing import Any

FENCE = chr(96) * 3

LEAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("windows_user_path", re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\s,;]+", re.IGNORECASE)),
    ("unix_home_path", re.compile(r"/(?:home|Users)/[A-Za-z0-9_.-]+")),
    ("api_token", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16})\b")),
    ("private_key_header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("dotenv_secret", re.compile(r"(?m)^[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY)\s*=\s*\S+")),
]

TOOLS: list[dict[str, Any]] = [
    {
        "name": "verify_mvc_witness",
        "description": "Verify in O(|V|+|E|) time that a candidate vertex list is a valid vertex cover, compute total weight, check 1-minimality, and emit a SHA-256 witness digest.",
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
                "serverInfo": {"name": "wyldcam-verification-mcp", "version": "0.1.0"},
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
    assert res_min["valid_cover"] is True, res_min
    assert res_min["is_1_minimal"] is True, res_min
    assert res_min["total_weight"] == 10, res_min

    res_red = verify_mvc_witness(cycle_edges, [1, 2, 3, 4])
    assert res_red["valid_cover"] is True and res_red["is_1_minimal"] is False, res_red
    assert res_red["redundant_vertices_count"] == 2, res_red

    res_schema = validate_structured_output('{"status":"ok","step":1}', ["status", "step"])
    assert res_schema["valid"] is True, res_schema

    sample_path = "C:" + "\\Users\\demo_account\\private_notes.txt"
    res_leak = scan_zero_leak(f"Loaded config from {sample_path}")
    assert res_leak["clean"] is False and res_leak["finding_count"] == 1, res_leak

    print("[PASS] graph_witness_mcp.py: all 4 deterministic verification self-tests passed.")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        run_selftest()
    else:
        serve_stdio()

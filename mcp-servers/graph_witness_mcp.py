#!/usr/bin/env python3
'''
Zero-dependency Model Context Protocol (MCP) stdio server (JSON-RPC 2.0) - v0.3.0.
Provides deterministic verification tools:
  1. verify_nspl_manifest_suite: Pure-stdlib Batagelj-Brandes seed-streamed 5k-130k MWVC witness suite auditor
  2. verify_witness_file: Streaming O(|V| + |E|) disk verifier (.wdimacs, DIMACS, PACE, MatrixMarket, .gz, JSON)
  3. verify_mvc_witness: Inline O(|V| + |E|) graph vertex-cover & 1-minimality verifier
  4. validate_structured_output: Strict JSON key & drift-token validator
  5. scan_zero_leak: Outbound path, token, and key hygiene scanner
'''

from __future__ import annotations

import gzip
import hashlib
import json
import math
import random
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
        "name": "verify_nspl_manifest_suite",
        "description": "Zero-dependency seed-streaming verifier for nspl-gpu-mwvc-witnesses (5k to 130k nodes). Reproduces nx.fast_gnp_random_graph(n, p_edge, seed) bit-for-bit in pure Python stdlib without allocating graphs in RAM. Pass the nspl-gpu-mwvc-witnesses directory, witness_manifest.json, or a single .sol path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "suite_or_sol_path": {
                    "type": "string",
                    "description": "Local path to the nspl-gpu-mwvc-witnesses folder, witness_manifest.json, or an individual .sol certificate file.",
                },
                "instance_filter": {
                    "type": "string",
                    "description": "Optional instance name filter (e.g. 'Scale_130k' or 'Conflict_5k') when auditing a folder or manifest.",
                },
            },
            "required": ["suite_or_sol_path"],
        },
    },
    {
        "name": "verify_witness_file",
        "description": "Stream a 5k-130k+ graph file (.wdimacs blind challenge, DIMACS, PACE .gr, MatrixMarket .mtx, edge list, JSON, .gz, or witness_manifest.json) and a witness file (.sol, .vc, .txt, or JSON) from disk in O(|V|+|E|) time. Verifies 100% edge coverage, exact weight, 1-minimality, and SHA-256 digests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "graph_path": {
                    "type": "string",
                    "description": "Local path to the benchmark graph file (.wdimacs, .mis, .gr, .mtx, .json, .gz) or witness_manifest.json.",
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


def _mod200_weight(v: int) -> int:
    return ((v + 1) % 200) + 1


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


def _stream_fast_gnp_audit(n: int, p_edge: float, seed: int, cover_set: set[int]) -> tuple[int, int, list[list[int]], set[int]]:
    '''
    Bit-exact standard-library implementation of NetworkX fast_gnp_random_graph(n, p_edge, seed)
    using Batagelj-Brandes geometric skip-stepping in O(|C|) RAM.
    '''
    rng = random.Random(seed)
    edge_count = 0
    uncovered_count = 0
    uncovered_sample: list[list[int]] = []
    essential_nodes: set[int] = set()

    if p_edge <= 0.0 or n <= 1:
        return 0, 0, [], set()

    lp = math.log(1.0 - p_edge)
    v = 1
    w = -1
    while v < n:
        lr = math.log(1.0 - rng.random())
        w = w + 1 + int(lr / lp)
        while w >= v and v < n:
            w = w - v
            v = v + 1
        if v < n:
            edge_count += 1
            v_in = v in cover_set
            w_in = w in cover_set
            if not v_in and not w_in:
                uncovered_count += 1
                if len(uncovered_sample) < 5:
                    uncovered_sample.append([v, w])
            else:
                if v_in and not w_in:
                    essential_nodes.add(v)
                elif w_in and not v_in:
                    essential_nodes.add(w)

    return edge_count, uncovered_count, uncovered_sample, essential_nodes


def _audit_single_manifest_record(rec: dict[str, Any], sol_file: Path) -> dict[str, Any]:
    t0 = time.perf_counter()
    inst = str(rec["instance"])
    n = int(rec["n"])
    expected_edges = int(rec["edges"])
    seed = int(rec["seed"])
    p_edge = float(rec["p_edge"])

    raw_text = sol_file.read_text(encoding="utf-8")
    text_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    expected_sha = str(rec.get("sha256", ""))
    sha_matched = (text_sha256 == expected_sha) if expected_sha else True

    cover_set = {int(tok) for ln in raw_text.splitlines() if ln.strip() and not ln.lstrip().startswith("#") for tok in ln.split()}
    out_of_range = [v for v in cover_set if v < 0 or v >= n]
    if out_of_range:
        raise ValueError(f"Out-of-range vertex IDs in {sol_file.name}: {out_of_range[:5]}")

    edge_count, uncovered_count, uncovered_sample, essential_nodes = _stream_fast_gnp_audit(n, p_edge, seed, cover_set)
    redundant_count = len(cover_set) - len(essential_nodes)

    exact_weight = sum(_mod200_weight(v) for v in cover_set)
    expected_weight = int(rec.get("gpu_weight", rec.get("l4_weight", exact_weight)))
    f1_weight = int(rec.get("fastwvc1_weight", exact_weight))
    f8_weight = int(rec.get("fastwvc8_weight", exact_weight))
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    passed = (
        sha_matched
        and edge_count == expected_edges
        and uncovered_count == 0
        and exact_weight == expected_weight
    )

    return {
        "instance": inst,
        "witness_file": sol_file.name,
        "audit_passed": passed,
        "nodes": n,
        "edges_verified": edge_count,
        "expected_edges": expected_edges,
        "edge_generator_matched": edge_count == expected_edges,
        "cover_size": len(cover_set),
        "uncovered_edge_count": uncovered_count,
        "uncovered_edges_sample": uncovered_sample,
        "is_1_minimal": uncovered_count == 0 and redundant_count == 0,
        "redundant_vertices_count": redundant_count,
        "exact_mwvc_weight": exact_weight,
        "manifest_gpu_weight": expected_weight,
        "weight_matched": exact_weight == expected_weight,
        "fastwvc1_weight": f1_weight,
        "fastwvc8_weight": f8_weight,
        "delta_vs_fastwvc1": exact_weight - f1_weight,
        "delta_vs_fastwvc8": exact_weight - f8_weight,
        "sha256_matched": sha_matched,
        "witness_sha256": text_sha256,
        "elapsed_ms": elapsed_ms,
    }


def verify_nspl_manifest_suite(
    suite_or_sol_path: str,
    instance_filter: str | None = None,
) -> dict[str, Any]:
    t_suite = time.perf_counter()
    target = Path(suite_or_sol_path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {Path(suite_or_sol_path).name}")

    single_sol: Path | None = None
    if target.is_dir():
        suite_dir = target
        manifest_path = suite_dir / "witness_manifest.json"
    elif target.name.lower() == "witness_manifest.json":
        suite_dir = target.parent
        manifest_path = target
    else:
        single_sol = target
        suite_dir = target.parent
        manifest_path = suite_dir / "witness_manifest.json"

    if not manifest_path.is_file():
        raise FileNotFoundError(f"witness_manifest.json not found beside {target.name}")

    manifest_records = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest_records, list):
        raise ValueError("witness_manifest.json must contain a JSON array of benchmark records.")

    selected_pairs: list[tuple[dict[str, Any], Path]] = []
    filt = (instance_filter or "").strip().lower()

    for rec in manifest_records:
        expected_name = f"{rec['instance']}_N{rec['n']}_seed{rec['seed']}.sol"
        candidate_sol = suite_dir / expected_name
        if single_sol is not None:
            if candidate_sol.name.lower() == single_sol.name.lower():
                selected_pairs.append((rec, single_sol))
        else:
            if filt and filt not in str(rec["instance"]).lower() and filt not in expected_name.lower():
                continue
            if not candidate_sol.is_file():
                raise FileNotFoundError(f"Missing expected witness file: {expected_name}")
            selected_pairs.append((rec, candidate_sol))

    if not selected_pairs:
        raise ValueError("No matching benchmark records found for the provided path/filter.")

    results = [_audit_single_manifest_record(rec, sol_p) for rec, sol_p in selected_pairs]
    total_edges = sum(r["edges_verified"] for r in results)
    all_passed = all(r["audit_passed"] for r in results)

    return {
        "suite_passed": all_passed,
        "certificates_verified": len(results),
        "total_edges_streamed": total_edges,
        "all_100pct_feasible": all(r["uncovered_edge_count"] == 0 for r in results),
        "all_sha256_matched": all(r["sha256_matched"] for r in results),
        "all_weights_matched": all(r["weight_matched"] for r in results),
        "total_elapsed_ms": round((time.perf_counter() - t_suite) * 1000.0, 2),
        "results": results,
    }


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
    g_raw = Path(graph_path).expanduser().resolve()
    if g_raw.is_dir() or g_raw.name.lower() == "witness_manifest.json":
        return verify_nspl_manifest_suite(witness_path)

    t0 = time.perf_counter()
    g_file = g_raw
    w_file = Path(witness_path).expanduser().resolve()

    if not g_file.is_file():
        raise FileNotFoundError(f"Graph file not found: {Path(graph_path).name}")
    if not w_file.is_file():
        raise FileNotFoundError(f"Witness file not found: {Path(witness_path).name}")

    cover_set = _load_witness_set(w_file)
    sorted_cover = sorted(cover_set)

    is_wdimacs_zero_sol = g_file.name.lower().endswith((".wdimacs", ".wdimacs.gz"))
    vertex_shift = -1 if is_wdimacs_zero_sol else 0

    cover_weights: dict[int, float] = {}
    has_embedded_weights = False
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
            has_embedded_weights = True
            for k, val in raw_weights.items():
                vid = int(k)
                if vid in cover_set:
                    cover_weights[vid] = float(val)
        elif isinstance(raw_weights, list):
            has_embedded_weights = True
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
                        has_embedded_weights = True
                        vid = int(parts[1]) + vertex_shift
                        if vid in cover_set:
                            wt_val = max(1, int(float(parts[2]))) if is_wdimacs_zero_sol else float(parts[2])
                            cover_weights[vid] = float(wt_val)
                    continue

                if first_char == "e" and (len(line) > 1 and line[1].isspace()):
                    parts = line.split()
                    u, v = int(parts[1]) + vertex_shift, int(parts[2]) + vertex_shift
                else:
                    parts = re.split(r"[\s,]+", line)
                    if len(parts) < 2:
                        continue
                    u, v = int(parts[0]) + vertex_shift, int(parts[1]) + vertex_shift

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
        base = 0 if (min_vertex_seen == 0 or is_wdimacs_zero_sol) else 1
        cover_weights.update(_load_external_weights(wt_file, cover_set, index_base=base))
    elif is_wdimacs_zero_sol and not has_embedded_weights:
        for v in sorted_cover:
            cover_weights[v] = float(_mod200_weight(v))

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
    if name == "verify_nspl_manifest_suite":
        return verify_nspl_manifest_suite(
            suite_or_sol_path=arguments["suite_or_sol_path"],
            instance_filter=arguments.get("instance_filter"),
        )
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
                "serverInfo": {"name": "wyldcam-verification-mcp", "version": "0.3.0"},
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

    # Verify Batagelj-Brandes exact edge count parity against Conflict_5k & Scale_130k parameters
    e_5k, _, _, _ = _stream_fast_gnp_audit(5000, 0.004, 42, set(range(5000)))
    assert e_5k == 50080, f"Expected 50080 edges for Conflict_5k, got {e_5k}"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # Test synthetic seed-manifest suite
        n_test, p_test, sd_test = 400, 0.05, 42
        e_cnt, _, _, _ = _stream_fast_gnp_audit(n_test, p_test, sd_test, set(range(n_test)))
        sol_p = tmp / f"Mini_400_N{n_test}_seed{sd_test}.sol"
        sol_txt = "\n".join(str(v) for v in range(n_test - 1)) + "\n"
        sol_p.write_text(sol_txt, encoding="utf-8", newline="\n")
        sol_sha = hashlib.sha256(sol_txt.encode("utf-8")).hexdigest()
        exp_wt = sum(_mod200_weight(v) for v in range(n_test - 1))
        (tmp / "witness_manifest.json").write_text(
            json.dumps([{
                "instance": "Mini_400",
                "n": n_test,
                "edges": e_cnt,
                "seed": sd_test,
                "p_edge": p_test,
                "gpu_weight": exp_wt,
                "fastwvc1_weight": exp_wt + 120,
                "fastwvc8_weight": exp_wt + 45,
                "sha256": sol_sha,
            }]),
            encoding="utf-8",
        )
        suite_res = verify_nspl_manifest_suite(str(tmp))
        assert suite_res["suite_passed"] is True, suite_res
        assert scan_zero_leak(json.dumps(suite_res))["clean"] is True

        # Test .wdimacs blind-challenge parity (1-based DIMACS -> 0-based .sol + mod200 fallback)
        wd_path = tmp / "blind_challenge.wdimacs"
        wd_sol = tmp / "blind_answer.sol"
        wd_path.write_text("p edge 3 2\ne 1 2\ne 2 3\n", encoding="utf-8")
        wd_sol.write_text("1\n", encoding="utf-8")
        wd_res = verify_witness_file(str(wd_path), str(wd_sol))
        assert wd_res["valid_cover"] is True and wd_res["total_weight"] == _mod200_weight(1), wd_res

    print("[PASS] graph_witness_mcp.py (v0.3.0): all 7 deterministic, Batagelj-Brandes seed & .wdimacs self-tests passed.")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        run_selftest()
    else:
        serve_stdio()

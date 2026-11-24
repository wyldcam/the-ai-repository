#!/usr/bin/env python3
'''
Repository Hygiene, Zero-Leak & MCP Stdio Protocol Gate.
Runs in GitHub Actions CI and optionally as a local Git pre-commit hook (--install-hook).
Enforces:
  1. Zero compiled binaries, archives, or secret files (.dll, .exe, .apk, .zip, .env, .pem, >1 MB)
  2. Zero workstation paths, API tokens, or private keys across all repo files
  3. Valid UTF-8 JSON and portable relative paths across all checked-in MCP IDE configs
  4. Live JSON-RPC 2.0 stdio handshake & tool execution against mcp-servers/graph_witness_mcp.py
'''

from __future__ import annotations

import importlib.util
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

FORBIDDEN_EXTENSIONS = {
    ".dll", ".exe", ".so", ".dylib", ".pyd", ".obj", ".o", ".lib", ".a",
    ".apk", ".dex", ".class", ".zip", ".7z", ".tar", ".gz", ".rar",
    ".pt", ".pth", ".onnx", ".safetensors", ".pem", ".key", ".pfx", ".p12",
}
FORBIDDEN_FILENAMES = {".env", ".env.local", ".env.production"}
TRANSIENT_BUILDERS = {"setup_ci.py", "upgrade_v020.py", "seed_artifacts.py", "clean_and_read.py", "upgrade_v030.py"}
MCP_CONFIG_PATHS = {".mcp.json", ".vscode/mcp.json", ".cursor/mcp.json", ".gemini/settings.json"}
ABS_PATH_RE = re.compile(r"(^[A-Za-z]:[\\/]|^/(?:Users|home|root|opt|var)/)")
MAX_FILE_BYTES = 1_048_576


def _load_leak_scanner(repo_root: Path):
    mcp_path = repo_root / "mcp-servers" / "graph_witness_mcp.py"
    spec = importlib.util.spec_from_file_location("graph_witness_mcp", mcp_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load mcp-servers/graph_witness_mcp.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.scan_zero_leak


def _list_repo_files(repo_root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repo_root,
        capture_output=True,
        check=True,
    )
    raw_entries = proc.stdout.decode("utf-8", errors="replace").split("\0")
    return [p for p in raw_entries if p and p not in TRANSIENT_BUILDERS]


def _verify_mcp_stdio_handshake(repo_root: Path) -> None:
    server_script = repo_root / "mcp-servers" / "graph_witness_mcp.py"
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "verify_mvc_witness",
                "arguments": {"edges": [[1, 2], [2, 3]], "cover": [2]},
            },
        },
    ]
    payload = "\n".join(json.dumps(r) for r in requests) + "\n"
    proc = subprocess.run(
        [sys.executable, str(server_script)],
        cwd=repo_root,
        input=payload,
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) != 3:
        raise AssertionError(f"Expected 3 JSON-RPC responses, got {len(lines)}: {proc.stdout}")

    init_resp = json.loads(lines[0])
    if init_resp.get("result", {}).get("protocolVersion") != "2024-11-05":
        raise AssertionError(f"Unexpected initialize response: {init_resp}")

    list_resp = json.loads(lines[1])
    tool_names = {t["name"] for t in list_resp.get("result", {}).get("tools", [])}
    expected_tools = {"verify_nspl_manifest_suite", "verify_witness_file", "verify_mvc_witness", "validate_structured_output", "scan_zero_leak"}
    if tool_names != expected_tools:
        raise AssertionError(f"Tool mismatch: expected {expected_tools}, got {tool_names}")

    call_resp = json.loads(lines[2])
    if call_resp.get("result", {}).get("isError") is not False:
        raise AssertionError(f"MCP tool call failed: {call_resp}")
    body = json.loads(call_resp["result"]["content"][0]["text"])
    if not (body.get("valid_cover") is True and body.get("is_1_minimal") is True):
        raise AssertionError(f"Unexpected tool verification output: {body}")


def install_precommit_hook(repo_root: Path) -> None:
    hook_path = repo_root / ".git" / "hooks" / "pre-commit"
    py_posix = Path(sys.executable).as_posix()
    hook_body = (
        "#!/usr/bin/env sh\n"
        "set -e\n"
        f'if [ -x "{py_posix}" ]; then\n'
        f'  "{py_posix}" scripts/repo_hygiene_gate.py\n'
        "elif command -v python >/dev/null 2>&1; then\n"
        "  python scripts/repo_hygiene_gate.py\n"
        "else\n"
        "  python3 scripts/repo_hygiene_gate.py\n"
        "fi\n"
    )
    hook_path.write_text(hook_body, encoding="utf-8", newline="\n")
    current_mode = hook_path.stat().st_mode
    hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[INSTALLED] Local Git pre-commit guard -> {hook_path.relative_to(repo_root)}")


def run_gate(repo_root: Path) -> int:
    scan_zero_leak = _load_leak_scanner(repo_root)
    rel_files = _list_repo_files(repo_root)
    violations: list[str] = []

    for rel in rel_files:
        fpath = repo_root / rel
        if not fpath.is_file():
            continue

        if any(ord(ch) < 32 or (0xE000 <= ord(ch) <= 0xF8FF) for ch in rel):
            violations.append(f"{repr(rel)}: corrupted/non-portable characters in filename")
            continue

        if "/" not in rel and fpath.stat().st_size == 0 and rel != ".nojekyll":
            violations.append(f"{rel}: empty 0-byte file in repository root")
            continue

        if fpath.name.lower() in FORBIDDEN_FILENAMES:
            violations.append(f"{rel}: forbidden secret filename")
            continue

        ext = fpath.suffix.lower()
        if ext in FORBIDDEN_EXTENSIONS:
            violations.append(f"{rel}: forbidden binary/archive extension '{ext}'")
            continue

        size = fpath.stat().st_size
        if size > MAX_FILE_BYTES:
            violations.append(f"{rel}: exceeds 1 MB repository limit ({size} bytes)")
            continue

        try:
            text = fpath.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            violations.append(f"{rel}: non-UTF-8 or binary content detected")
            continue

        leak_res = scan_zero_leak(text)
        if not leak_res["clean"]:
            for hit in leak_res["findings"]:
                violations.append(f"{rel}:{hit['line']} -> {hit['rule']} ({hit['preview']})")

        if ext == ".json":
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                violations.append(f"{rel}: invalid JSON at pos {exc.pos}: {exc.msg}")
                continue

            if rel in MCP_CONFIG_PATHS:
                container = parsed.get("mcpServers") or parsed.get("servers") or {}
                for srv_name, cfg in container.items():
                    cmd = str(cfg.get("command", ""))
                    args = [str(a) for a in (cfg.get("args") or [])]
                    for item in [cmd, *args]:
                        if ABS_PATH_RE.search(item):
                            violations.append(f"{rel} ({srv_name}): non-portable machine path '{item}'")

    if violations:
        print("[FAIL] Repository hygiene gate blocked the following issues:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    _verify_mcp_stdio_handshake(repo_root)
    print(f"[PASS] repo_hygiene_gate.py: {len(rel_files)} files clean, 4 MCP configs portable, stdio JSON-RPC handshake OK.")
    return 0


if __name__ == "__main__":
    root_dir = Path(__file__).resolve().parent.parent
    if "--install-hook" in sys.argv:
        install_precommit_hook(root_dir)
    sys.exit(run_gate(root_dir))

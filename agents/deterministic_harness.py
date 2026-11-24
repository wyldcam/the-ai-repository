#!/usr/bin/env python3
'''
Local-first deterministic execution harness for tool-augmented AI agents.
Treats any LLM callable as an untrusted proposer and enforces invariant pinning,
raw JSON schema compliance, bounded diagnostic retries, and outbound leak hygiene.
'''

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

FENCE = chr(96) * 3

PATH_OR_SECRET_RE = re.compile(
    r'([A-Za-z]:[\\/]+Users[\\/]+[^\s",;]+|/(?:home|Users)/[A-Za-z0-9_.-]+|\bsk-[A-Za-z0-9_-]{16,}\b)',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExecutionContract:
    task_id: str
    pinned_invariants: tuple[str, ...]
    required_keys: tuple[str, ...] = (
        "step_index",
        "pinned_invariants",
        "quarantined_assumptions",
        "action",
        "verification_evidence",
        "status",
    )
    max_attempts: int = 3


@dataclass
class HarnessResult:
    ok: bool
    attempts_used: int
    envelope: dict[str, Any] | None
    diagnostics: list[str] = field(default_factory=list)


def validate_envelope(raw_output: str, contract: ExecutionContract) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    text = raw_output.strip()

    if PATH_OR_SECRET_RE.search(text):
        errors.append("Outbound hygiene violation: local user path or secret token detected.")
        return None, errors

    if text.startswith(FENCE):
        errors.append("Envelope drift: raw JSON required without Markdown code fences.")
        return None, errors

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON at char {exc.pos}: {exc.msg}")
        return None, errors

    if not isinstance(data, dict):
        errors.append("Root JSON payload must be an object.")
        return None, errors

    missing = [k for k in contract.required_keys if k not in data]
    if missing:
        errors.append(f"Missing required contract keys: {missing}")

    reported_invariants = set(data.get("pinned_invariants") or [])
    dropped = [inv for inv in contract.pinned_invariants if inv not in reported_invariants]
    if dropped:
        errors.append(f"Dropped pinned invariants: {dropped}")

    if data.get("status") == "complete" and not str(data.get("verification_evidence", "")).strip():
        errors.append("Cannot mark status='complete' without non-empty verification_evidence.")

    return (data if not errors else None), errors


def run_guarded_step(
    model_fn: Callable[[str], str],
    base_prompt: str,
    contract: ExecutionContract,
) -> HarnessResult:
    prompt = base_prompt
    all_diagnostics: list[str] = []

    for attempt in range(1, contract.max_attempts + 1):
        raw = model_fn(prompt)
        envelope, errors = validate_envelope(raw, contract)
        if envelope is not None:
            return HarnessResult(ok=True, attempts_used=attempt, envelope=envelope, diagnostics=all_diagnostics)

        joined = "; ".join(errors)
        all_diagnostics.append(f"Attempt {attempt}: {joined}")
        prompt = (
            f"{base_prompt}\n\n"
            f"[CONTRACT REJECTION #{attempt}]: {joined}\n"
            f"Re-emit ONLY a raw JSON object preserving invariants: {list(contract.pinned_invariants)}"
        )

    return HarnessResult(ok=False, attempts_used=contract.max_attempts, envelope=None, diagnostics=all_diagnostics)


def run_selftest() -> None:
    contract = ExecutionContract(
        task_id="audit-01",
        pinned_invariants=("Zero external network calls", "Strict O(|V|+|E|) verification"),
    )

    responses = iter([
        f"{FENCE}json\n{{\"step_index\": 1}}\n{FENCE}",
        json.dumps({
            "step_index": 1,
            "pinned_invariants": ["Zero external network calls", "Strict O(|V|+|E|) verification"],
            "quarantined_assumptions": [],
            "action": {"kind": "tool_call", "target": "verify_mvc_witness", "summary": "Verify witness certificate"},
            "verification_evidence": "SHA-256 matched; 0 uncovered edges",
            "status": "complete",
        }),
    ])

    result = run_guarded_step(lambda _p: next(responses), "Audit witness.", contract)
    assert result.ok is True and result.attempts_used == 2, result

    leaked_path = "C:" + "\\Users\\local_dev\\key.pem"
    leak_res = run_guarded_step(lambda _p: json.dumps({"note": leaked_path}), "Test leak.", contract)
    assert leak_res.ok is False and "hygiene violation" in leak_res.diagnostics[0], leak_res

    print("[PASS] deterministic_harness.py: zero-drift retry & leak-guard self-test passed.")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        run_selftest()
    else:
        print("Import run_guarded_step or run with --selftest.")

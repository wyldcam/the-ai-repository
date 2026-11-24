# Agents & Execution Harnesses

Standalone, local-first reference harnesses treating LLMs as untrusted proposers backed by deterministic validation gates.

## `deterministic_harness.py`

Wraps any `Callable[[str], str]` model adapter with:
- **Invariant Pinning:** Verifies every active hard constraint remains present in the step ledger.
- **Strict Envelope Parsing:** Rejects Markdown code-fence drift and missing contract keys, feeding exact diagnostics back to the model for bounded deterministic convergence.
- **Outbound Leak Blocking:** Halts execution if an agent output attempts to emit local workstation paths or secret tokens.

```bash
python agents/deterministic_harness.py --selftest
```

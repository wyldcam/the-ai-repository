#!/usr/bin/env python3
'''
Stages repository Markdown and Lean 4 artifacts into _site_docs/ for MkDocs Material,
rewriting repo-relative file links so `mkdocs build --strict` produces zero broken links.
'''

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

REPO_BLOB_BASE = "https://github.com/wyldcam/the-ai-repository/blob/main/"
LINK_RE = re.compile(r"(\[[^\]]+\]\()([^)\s]+)(\))")

DOC_ROUTE_MAP = {
    "README.md": "index.md",
    "EVALUATOR_QUICKSTART.md": "quickstart.md",
    "mcp-servers": "mcp-server.md",
    "mcp-servers/README.md": "mcp-server.md",
    "prompts": "zero-drift-pack.md",
    "prompts/README.md": "zero-drift-pack.md",
    "prompts/zero-drift-pack": "zero-drift-pack.md",
    "prompts/zero-drift-pack/system_contract.md": "zero-drift-pack.md",
    "agents": "agent-harness.md",
    "agents/README.md": "agent-harness.md",
    "research": "research/001-asymmetric-witness-verification.md",
    "research/README.md": "research/001-asymmetric-witness-verification.md",
    "research/001-asymmetric-witness-verification.md": "research/001-asymmetric-witness-verification.md",
    "research/VertexCoverSoundness.lean": "research/formal-verification.md",
}

MATHJAX_CONFIG = '''window.MathJax = {
  tex: {
    inlineMath: [["\\\\(", "\\\\)"]],
    displayMath: [["\\\\[", "\\\\]"]],
    processEscapes: true,
    processEnvironments: true
  },
  options: {
    ignoreHtmlClass: ".*|",
    processHtmlClass: "arithmatex"
  }
};
'''


def _rewrite_links(markdown_text: str, src_rel_dir: str, dest_doc_rel: str, root: Path) -> str:
    dest_parent = os.path.dirname(dest_doc_rel)

    def _replace(match: re.Match[str]) -> str:
        prefix, target, suffix = match.group(1), match.group(2), match.group(3)
        if target.startswith(("http://", "https://", "mailto:", "#")):
            return match.group(0)

        anchor = ""
        clean_target = target
        if "#" in target:
            clean_target, anchor = target.split("#", 1)
            anchor = "#" + anchor

        resolved = (root / src_rel_dir / clean_target).resolve()
        try:
            repo_rel = resolved.relative_to(root).as_posix()
        except ValueError:
            return match.group(0)

        if repo_rel in DOC_ROUTE_MAP:
            mapped_doc = DOC_ROUTE_MAP[repo_rel]
            rel_url = os.path.relpath(mapped_doc, dest_parent or ".").replace("\\", "/")
            return f"{prefix}{rel_url}{anchor}{suffix}"

        return f"{prefix}{REPO_BLOB_BASE}{repo_rel}{anchor}{suffix}"

    return LINK_RE.sub(_replace, markdown_text)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    out = root / "_site_docs"
    if out.exists():
        shutil.rmtree(out)
    (out / "research").mkdir(parents=True, exist_ok=True)
    (out / "javascripts").mkdir(parents=True, exist_ok=True)

    (out / "javascripts" / "mathjax.js").write_text(MATHJAX_CONFIG, encoding="utf-8", newline="\n")

    pages = [
        ("README.md", "", "index.md"),
        ("EVALUATOR_QUICKSTART.md", "", "quickstart.md"),
        ("mcp-servers/README.md", "mcp-servers", "mcp-server.md"),
        ("agents/README.md", "agents", "agent-harness.md"),
        ("research/001-asymmetric-witness-verification.md", "research", "research/001-asymmetric-witness-verification.md"),
    ]

    for src_rel, src_dir, dest_rel in pages:
        raw = (root / src_rel).read_text(encoding="utf-8")
        rewritten = _rewrite_links(raw, src_dir, dest_rel, root)
        (out / dest_rel).write_text(rewritten, encoding="utf-8", newline="\n")

    # Combine Zero-Drift Prompt Contract + Schema into a single navigable page
    fence = chr(96) * 3
    contract_md = (root / "prompts/zero-drift-pack/system_contract.md").read_text(encoding="utf-8")
    schema_json = (root / "prompts/zero-drift-pack/step_envelope.schema.json").read_text(encoding="utf-8")
    zero_drift_combined = (
        f"{contract_md.rstrip()}\n\n---\n\n"
        f"## Step Envelope JSON Schema (Draft 2020-12)\n\n"
        f"Source: [`prompts/zero-drift-pack/step_envelope.schema.json`]({REPO_BLOB_BASE}prompts/zero-drift-pack/step_envelope.schema.json)\n\n"
        f"{fence}json\n{schema_json.rstrip()}\n{fence}\n"
    )
    (out / "zero-drift-pack.md").write_text(
        _rewrite_links(zero_drift_combined, "prompts/zero-drift-pack", "zero-drift-pack.md", root),
        encoding="utf-8",
        newline="\n",
    )

    # Stage Lean 4 Soundness Proof if present
    lean_file = root / "research" / "VertexCoverSoundness.lean"
    if lean_file.is_file():
        lean_code = lean_file.read_text(encoding="utf-8")
        lean_page = (
            "# Formal Soundness Proof (Lean 4)\n\n"
            "Post-solve polynomial-time vertex cover soundness formalization.\n\n"
            f"Source file: [`research/VertexCoverSoundness.lean`]({REPO_BLOB_BASE}research/VertexCoverSoundness.lean)\n\n"
            f"{fence}lean\n{lean_code.rstrip()}\n{fence}\n"
        )
    else:
        lean_page = (
            "# Formal Soundness Proof (Lean 4)\n\n"
            f"See repository [`research/`]({REPO_BLOB_BASE}research) directory for formal verification modules.\n"
        )
    (out / "research" / "formal-verification.md").write_text(lean_page, encoding="utf-8", newline="\n")
    print("[OK] Staged documentation portal into _site_docs/")


if __name__ == "__main__":
    main()

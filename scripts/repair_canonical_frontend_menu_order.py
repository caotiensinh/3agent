#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSOLIDATOR = ROOT / "scripts" / "consolidate_workspace_frontend.py"

GITHUB_ROW = r'''      <button class="menu-row" type="button" data-action="github">
        <span class="menu-icon white"><svg viewBox="0 0 24 24"><path d="M9 19c-4 1.2-4-2-5-2.5M14 22v-3.1c0-.9.1-1.5-.5-2.1 2.8-.3 5.7-1.4 5.7-6.2a4.9 4.9 0 0 0-1.3-3.4 4.6 4.6 0 0 0-.1-3.4S16.8 3.4 14 5a11.7 11.7 0 0 0-5 0C6.2 3.4 5.2 3.8 5.2 3.8a4.6 4.6 0 0 0-.1 3.4 4.9 4.9 0 0 0-1.3 3.4c0 4.8 2.9 5.9 5.7 6.2-.5.5-.6 1-.6 2.1V22"/></svg></span>
        <span><span class="menu-title">GitHub</span><span class="menu-sub">Repository access</span></span><span class="menu-state">Operator only</span>
      </button>
'''

GMAIL_ROW = r'''      <button class="menu-row" type="button" data-action="gmail" data-connect-action="true" role="menuitem">
        <span class="menu-icon white">M</span>
        <span><div class="menu-title">Gmail</div><div class="menu-sub">Read and manage Gmail</div></span><span class="menu-state">Connect</span>
      </button>
'''

ORDER = (
    'data-action="figma"',
    'data-action="canva"',
    'data-action="gmail"',
    'data-action="github"',
)


def _load_consolidator():
    spec = importlib.util.spec_from_file_location("workspace_frontend_consolidator", CONSOLIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load workspace frontend consolidator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repair(html: str) -> str:
    for marker in ORDER:
        if html.count(marker) != 1:
            raise RuntimeError(f"canonical integration menu expected exactly one {marker}")

    positions = [html.index(marker) for marker in ORDER]
    if positions == sorted(positions):
        return html

    if html.count(GITHUB_ROW) != 1 or html.count(GMAIL_ROW) != 1:
        raise RuntimeError("canonical integration menu rows do not match the reviewed contract")

    without_github = html.replace(GITHUB_ROW, "", 1)
    if without_github.count(GMAIL_ROW) != 1:
        raise RuntimeError("canonical Gmail menu row became ambiguous during reorder")
    repaired = without_github.replace(GMAIL_ROW, GMAIL_ROW + GITHUB_ROW, 1)

    final_positions = [repaired.index(marker) for marker in ORDER]
    if final_positions != sorted(final_positions):
        raise RuntimeError("canonical integration menu order repair did not converge")
    return repaired


def main() -> int:
    consolidator = _load_consolidator()
    html, config_markup, config_js = consolidator._load_canonical_authority()
    repaired = _repair(html)
    digest, changed = consolidator._write_canonical(repaired, config_markup, config_js)
    print(json.dumps({
        "status": "repaired" if changed else "noop",
        "final_html_sha256": digest,
        "rewritten_files": changed,
        "integration_order": list(ORDER),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PKG = SRC / "three_agent"
CANONICAL = PKG / "workspace_frontend.py"
TEST_FILE = ROOT / "tests" / "test_workspace_frontend_canonicalization.py"
V18_SOURCE = PKG / "workspace_frontend_v18.py"
VERSION_MODULE_RE = re.compile(r"(?:three_agent\.)?workspace_frontend_v\d+(?:_part\d+)?$")
VERSION_REF_RE = re.compile(r"workspace_frontend_v\d+(?:_part\d+)?")
VERSION_FILE_RE = re.compile(r"workspace_frontend_v\d+(?:_part\d+)?\.py")
VERSION_HTML_RE = re.compile(r"WORKSPACE_HTML_V\d+")
PRESERVED_SYMBOLS = {
    "_replace_once",
    "_insert_after_workflow_description",
    "config_js",
    "config_markup",
    "html",
}

ASSET_UI_CSS = r'''
.security-asset-exact-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-left:auto}.security-asset-exact-state{font-size:9px;color:#8d929c;max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.security-asset-exact-state.ok{color:#9ecfb3}.security-asset-exact-state.warn{color:#e3c895}.security-asset-exact-state.error{color:#e0a4a4}
'''

ASSET_UI_JS = r'''
(function(){
const root=document.getElementById('secCfgAssets');
const configTab=document.getElementById('securityConfigTab');
if(!root||!configTab)return;
let configFingerprint='';
let snapshotLoading=false;
function toast(message){if(typeof window.showToast==='function')window.showToast(message)}
function confirmation(){const field=document.getElementById('secCfgStrongConfirmation');return field?field.value.trim():''}
async function jsonRequest(path,options={}){const response=await fetch(path,{credentials:'same-origin',...options});let data={};try{data=await response.json()}catch(e){}if(!response.ok){const error=new Error(data.error||data.code||('HTTP '+response.status));error.status=response.status;error.code=data.code||'';throw error}return data}
async function loadFingerprint(){if(snapshotLoading)return;snapshotLoading=true;try{const data=await jsonRequest('/api/security/assets/config');configFingerprint=String(data.config_fingerprint||'');decorateEditors()}catch(e){configFingerprint=''}finally{snapshotLoading=false}}
function assetFrom(box){return {asset_id:box.querySelector('.secAssetId').value.trim(),role:box.querySelector('.secAssetRole').value.trim(),management_host:box.querySelector('.secAssetHost').value.trim(),collector_capabilities:Array.from(box.querySelectorAll('.secAssetCaps input:checked')).map(x=>x.value),allowed_tcp_ports:box.querySelector('.secAssetPorts').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number),data_class:box.querySelector('.secAssetClass').value,enabled:box.querySelector('.secAssetEnabled').checked,credential_ref:box.querySelector('.secAssetCredential').value.trim()||null}}
function stateNode(box){let node=box.querySelector('.security-asset-exact-state');if(!node){node=document.createElement('span');node.className='security-asset-exact-state';const head=box.querySelector('.security-asset-head');if(head)head.appendChild(node)}return node}
function setState(box,message,kind=''){const node=stateNode(box);node.textContent=message;node.className='security-asset-exact-state'+(kind?' '+kind:'')}
async function handleConflict(box,error){if(error.status===409||error.code==='SECURITY_ASSET_CONFIG_STALE'){setState(box,'Stale configuration — reload before retry','warn');toast('Approved asset changed elsewhere. Reload Configuration before retry.');await loadFingerprint();const reload=document.getElementById('secCfgReload');if(reload)reload.click();return true}return false}
async function saveAsset(box){if(!configFingerprint){setState(box,'Load asset snapshot first','warn');await loadFingerprint();if(!configFingerprint)return}setState(box,'Saving exact asset…');try{const data=await jsonRequest('/api/security/assets/upsert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset:assetFrom(box),expected_config_fingerprint:configFingerprint,confirmation:confirmation()})});configFingerprint=String(data.config_fingerprint||configFingerprint);setState(box,(data.action||'saved')+' · network execution=false','ok');const field=document.getElementById('secCfgStrongConfirmation');if(field)field.value='';toast('Approved asset saved without network execution')}catch(e){if(await handleConflict(box,e))return;setState(box,'Rejected: '+e.message,'error');toast('Approved asset save blocked: '+e.message)}}
async function disableAsset(box){const assetId=box.querySelector('.secAssetId').value.trim();if(!assetId){setState(box,'Asset ID is required','error');return}if(!configFingerprint){await loadFingerprint();if(!configFingerprint)return}setState(box,'Disabling exact asset…');try{const data=await jsonRequest('/api/security/assets/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset_id:assetId,expected_config_fingerprint:configFingerprint,confirmation:confirmation()})});configFingerprint=String(data.config_fingerprint||configFingerprint);box.querySelector('.secAssetEnabled').checked=false;setState(box,'disabled · network execution=false','ok');const field=document.getElementById('secCfgStrongConfirmation');if(field)field.value='';toast('Approved asset disabled; no network action was executed')}catch(e){if(await handleConflict(box,e))return;setState(box,'Rejected: '+e.message,'error');toast('Approved asset disable blocked: '+e.message)}}
function decorate(box){if(box.dataset.exactAssetControls==='1')return;box.dataset.exactAssetControls='1';const head=box.querySelector('.security-asset-head');if(!head)return;const existing=head.querySelector('.secAssetRemove');if(existing)existing.textContent='Remove draft row';const actions=document.createElement('div');actions.className='security-asset-exact-actions';const save=document.createElement('button');save.type='button';save.className='soft-btn';save.textContent='Save asset';save.onclick=()=>saveAsset(box);const disable=document.createElement('button');disable.type='button';disable.className='soft-btn';disable.textContent='Disable asset';disable.onclick=()=>disableAsset(box);actions.append(save,disable);head.appendChild(actions);stateNode(box)}
function decorateEditors(){for(const box of root.querySelectorAll('.security-asset-editor'))decorate(box)}
new MutationObserver(decorateEditors).observe(root,{childList:true,subtree:true});
configTab.addEventListener('click',()=>window.setTimeout(loadFingerprint,0));
document.getElementById('secCfgReload')?.addEventListener('click',()=>window.setTimeout(loadFingerprint,80));
decorateEditors();
})();
'''

ASSET_UI_MARKERS = (
    "security-asset-exact-actions",
    "Save asset",
    "Disable asset",
    "Remove draft row",
    "expected_config_fingerprint",
    "SECURITY_ASSET_CONFIG_STALE",
    "network execution=false",
    "/api/security/assets/upsert",
    "/api/security/assets/disable",
)
ASSET_UI_PREREQUISITES = (
    'id="secCfgAssets"',
    'id="securityConfigTab"',
    'id="secCfgStrongConfirmation"',
    "secAssetCredential",
    "credential_ref",
)


def _variant_files() -> list[Path]:
    return sorted(PKG.glob("workspace_frontend_v*.py"), key=lambda p: p.name)


def _external_python_files(variants: set[Path]) -> list[Path]:
    paths: list[Path] = []
    for base in (SRC, ROOT / "tests", ROOT / "scripts"):
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            resolved = path.resolve()
            if resolved in variants or resolved == Path(__file__).resolve():
                continue
            paths.append(path)
    return sorted(paths)


def _validate_import_contract(paths: list[Path]) -> None:
    violations: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if "workspace_frontend_v" not in text:
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            raise RuntimeError(f"cannot parse {path}: {exc}") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if VERSION_MODULE_RE.search(module):
                    for alias in node.names:
                        name = alias.name
                        if name in PRESERVED_SYMBOLS or VERSION_HTML_RE.fullmatch(name):
                            continue
                        violations.append(f"{path}: unsupported import {module}.{name}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if VERSION_MODULE_RE.search(alias.name):
                        violations.append(
                            f"{path}: module-style import {alias.name} requires manual semantic review"
                        )
    if violations:
        raise RuntimeError("unsafe workspace frontend imports:\n" + "\n".join(violations))


def _eval_string_expr(node: ast.AST, env: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in env:
        return env[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _eval_string_expr(node.left, env) + _eval_string_expr(node.right, env)
    raise RuntimeError(f"unsupported V18 string expression: {ast.dump(node, include_attributes=False)}")


def _replace_or_already(source: str, old: str, new: str, label: str) -> str:
    old_count = source.count(old)
    if old_count == 1:
        return source.replace(old, new, 1)
    new_count = source.count(new)
    if old_count == 0 and new_count == 1:
        return source
    raise RuntimeError(
        f"effective V18 patch '{label}' is ambiguous: old_count={old_count}, new_count={new_count}"
    )


def _asset_ui_overlay(source: str) -> str:
    """Preserve exact-asset mutation UI independently of historical frontend generation names."""

    present = [marker for marker in ASSET_UI_MARKERS if marker in source]
    if len(present) == len(ASSET_UI_MARKERS):
        return source
    if present:
        missing = sorted(set(ASSET_UI_MARKERS) - set(present))
        raise RuntimeError(
            "partial exact-asset frontend contract detected; missing markers: " + ", ".join(missing)
        )
    missing_prerequisites = [marker for marker in ASSET_UI_PREREQUISITES if marker not in source]
    if missing_prerequisites:
        raise RuntimeError(
            "cannot restore exact-asset frontend contract; missing prerequisites: "
            + ", ".join(missing_prerequisites)
        )
    if source.count("</style>") != 1 or source.count("</body>") != 1:
        raise RuntimeError("exact-asset frontend overlay requires one </style> and one </body> boundary")
    updated = source.replace("</style>", ASSET_UI_CSS + "</style>", 1)
    updated = updated.replace("</body>", "<script>" + ASSET_UI_JS + "</script>\n</body>", 1)
    for marker in ASSET_UI_MARKERS:
        if marker not in updated:
            raise RuntimeError(f"exact-asset frontend overlay failed to preserve marker: {marker}")
    return updated


def _replay_v18_effective(predecessor_html: str) -> str:
    """Replay V18 source with idempotent semantics over reconciled V17.

    Branch reconciliation can make a V18 replacement already present in V17. In that
    case the effective behavior is already integrated and must not be applied twice.
    Every patch must therefore prove either exactly one old marker or exactly one new
    marker; anything else fails closed.
    """

    tree = ast.parse(V18_SOURCE.read_text(encoding="utf-8"), filename=str(V18_SOURCE))
    env: dict[str, str] = {
        "WORKSPACE_HTML_V17": predecessor_html,
        "html": predecessor_html,
    }
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        target = node.targets[0].id
        value = node.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "_replace_once":
            if len(value.args) != 4 or not isinstance(value.args[0], ast.Name) or value.args[0].id != "html":
                raise RuntimeError("unsupported V18 _replace_once call shape")
            old = _eval_string_expr(value.args[1], env)
            new = _eval_string_expr(value.args[2], env)
            label = _eval_string_expr(value.args[3], env)
            env[target] = _replace_or_already(env["html"], old, new, label)
            if target == "html":
                env["html"] = env[target]
            continue
        if isinstance(value, ast.Name) and value.id == "WORKSPACE_HTML_V17":
            env[target] = predecessor_html
            continue
        try:
            env[target] = _eval_string_expr(value, env)
        except RuntimeError:
            if target == "WORKSPACE_HTML_V18" and isinstance(value, ast.Name) and value.id == "html":
                env[target] = env["html"]
            else:
                raise
    final = env.get("WORKSPACE_HTML_V18", env["html"])
    if not final.strip():
        raise RuntimeError("effective V18 replay produced empty HTML")
    return final


def _load_authority() -> tuple[str, str, str]:
    """Resolve effective final UI without restoring deleted security generation files."""

    shim_name = "three_agent.workspace_frontend_security_v3"
    sys.path.insert(0, str(SRC))
    previous_shim = sys.modules.get(shim_name)
    try:
        v15 = importlib.import_module("three_agent.workspace_frontend_v15")
        security = importlib.import_module("three_agent.workspace_frontend_security")
        shim = types.ModuleType(shim_name)
        shim.WORKSPACE_HTML_SECURITY_V3 = security.build_security_v3(v15.WORKSPACE_HTML_V15)
        sys.modules[shim_name] = shim
        v17 = importlib.import_module("three_agent.workspace_frontend_v17")
        predecessor_html = getattr(v17, "WORKSPACE_HTML_V17")
        html = _asset_ui_overlay(_replay_v18_effective(predecessor_html))
        config_markup = getattr(v15, "config_markup")
        config_js = getattr(v15, "config_js")
    finally:
        if previous_shim is None:
            sys.modules.pop(shim_name, None)
        else:
            sys.modules[shim_name] = previous_shim
        try:
            sys.path.remove(str(SRC))
        except ValueError:
            pass
    for label, value in (("final HTML", html), ("config markup", config_markup), ("config JS", config_js)):
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"workspace frontend {label} did not resolve to a non-empty string")
    return html, config_markup, config_js


def _load_canonical_authority() -> tuple[str, str, str]:
    """Repair an already-consolidated canonical frontend without reintroducing generations."""

    sys.path.insert(0, str(SRC))
    module_name = "three_agent.workspace_frontend"
    previous = sys.modules.pop(module_name, None)
    try:
        module = importlib.import_module(module_name)
        html = _asset_ui_overlay(getattr(module, "WORKSPACE_HTML"))
        config_markup = getattr(module, "config_markup")
        config_js = getattr(module, "config_js")
    finally:
        sys.modules.pop(module_name, None)
        if previous is not None:
            sys.modules[module_name] = previous
        try:
            sys.path.remove(str(SRC))
        except ValueError:
            pass
    for label, value in (("final HTML", html), ("config markup", config_markup), ("config JS", config_js)):
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"workspace frontend {label} did not resolve to a non-empty string")
    return html, config_markup, config_js


def _literal(value: str) -> str:
    lines = value.splitlines(keepends=True)
    if not lines:
        return "''"
    return "(\n" + "\n".join(f"    {line!r}" for line in lines) + "\n)"


def _canonical_source(html: str, config_markup: str, config_js: str) -> str:
    return (
        "from __future__ import annotations\n\n"
        "\n"
        "def _replace_once(source: str, old: str, new: str, label: str) -> str:\n"
        "    count = source.count(old)\n"
        "    if count != 1:\n"
        "        raise RuntimeError(\n"
        "            f\"WorkSpace frontend canonical patch '{label}' expected exactly one match, got {count}\"\n"
        "        )\n"
        "    return source.replace(old, new, 1)\n\n\n"
        "def _insert_after_workflow_description(document: str, markup: str) -> str:\n"
        "    \"\"\"Insert workflow-draft markup after the stable workflowDescription textarea.\"\"\"\n"
        "    token = 'id=\"workflowDescription\"'\n"
        "    count = document.count(token)\n"
        "    if count != 1:\n"
        "        raise RuntimeError(\n"
        "            \"workflow-draft-library-markup: expected exactly one workflowDescription id, \"\n"
        "            f\"found {count}\"\n"
        "        )\n"
        "    token_at = document.index(token)\n"
        "    open_at = document.rfind(\"<textarea\", 0, token_at + 1)\n"
        "    close_at = document.find(\"</textarea>\", token_at)\n"
        "    if open_at < 0 or close_at < 0 or open_at > token_at:\n"
        "        raise RuntimeError(\n"
        "            \"workflow-draft-library-markup: workflowDescription must remain a textarea\"\n"
        "        )\n"
        "    insert_at = close_at + len(\"</textarea>\")\n"
        "    return document[:insert_at] + \"\\n\" + markup + document[insert_at:]\n\n\n"
        "config_markup = " + _literal(config_markup) + "\n\n"
        "config_js = " + _literal(config_js) + "\n\n"
        "WORKSPACE_HTML = " + _literal(html) + "\n\n"
        "html = WORKSPACE_HTML\n"
    )


def _rewrite_references(paths: list[Path]) -> list[Path]:
    changed: list[Path] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        updated = VERSION_REF_RE.sub("workspace_frontend", text)
        updated = VERSION_FILE_RE.sub("workspace_frontend.py", updated)
        updated = VERSION_HTML_RE.sub("WORKSPACE_HTML", updated)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed.append(path)
    return changed


def _test_source(expected_sha256: str) -> str:
    return f'''from __future__ import annotations\n\nimport hashlib\nimport re\nimport unittest\nfrom pathlib import Path\n\nfrom three_agent.workspace_frontend import WORKSPACE_HTML, _insert_after_workflow_description, config_js, config_markup\n\nROOT = Path(__file__).resolve().parents[1]\nEXPECTED_SHA256 = "{expected_sha256}"\n\n\nclass WorkspaceFrontendCanonicalizationTests(unittest.TestCase):\n    def test_rendered_frontend_matches_effective_canonical_authority(self) -> None:\n        actual = hashlib.sha256(WORKSPACE_HTML.encode("utf-8")).hexdigest()\n        self.assertEqual(actual, EXPECTED_SHA256)\n\n    def test_preserved_composition_contract_symbols_are_available(self) -> None:\n        self.assertIn("securityConfigView", config_markup)\n        self.assertIn("secCfgStatus", config_js)\n        sample = '<textarea id="workflowDescription"></textarea><div>tail</div>'\n        rendered = _insert_after_workflow_description(sample, '<div id="draft">draft</div>')\n        self.assertIn('</textarea>\\n<div id="draft">draft</div><div>tail</div>', rendered)\n\n    def test_final_frontend_contains_business_document_and_security_contracts(self) -> None:\n        for marker in (\n            'application/pdf',\n            'uploadProcessingLabel',\n            'id="securityBoundaryView"',\n            'id="securityConfigView"',\n            'Save asset',\n            'Disable asset',\n            'Remove draft row',\n            'expected_config_fingerprint',\n            'SECURITY_ASSET_CONFIG_STALE',\n            'network execution=false',\n            '/api/security/assets/upsert',\n            '/api/security/assets/disable',\n            'secAssetCredential',\n            'credential_ref',\n        ):\n            self.assertIn(marker, WORKSPACE_HTML)\n\n    def test_no_physical_frontend_generation_modules_remain(self) -> None:\n        package = ROOT / "src" / "three_agent"\n        self.assertEqual(list(package.glob("workspace_frontend_v*.py")), [])\n\n    def test_runtime_code_has_no_stale_frontend_generation_references(self) -> None:\n        pattern = re.compile("workspace_frontend_" + r"v\\d")\n        stale = []\n        migration = (ROOT / "scripts" / "consolidate_workspace_frontend.py").resolve()\n        for base in (ROOT / "src", ROOT / "tests", ROOT / "scripts"):\n            for path in base.rglob("*.py"):\n                if path.resolve() == migration:\n                    continue\n                text = path.read_text(encoding="utf-8")\n                if pattern.search(text):\n                    stale.append(str(path.relative_to(ROOT)))\n        self.assertEqual(stale, [])\n\n\nif __name__ == "__main__":\n    unittest.main()\n'''


def _write_canonical(html: str, config_markup: str, config_js: str) -> tuple[str, list[str]]:
    digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
    changed: list[str] = []
    canonical_source = _canonical_source(html, config_markup, config_js)
    test_source = _test_source(digest)
    if not CANONICAL.exists() or CANONICAL.read_text(encoding="utf-8") != canonical_source:
        CANONICAL.write_text(canonical_source, encoding="utf-8")
        changed.append(str(CANONICAL.relative_to(ROOT)))
    if not TEST_FILE.exists() or TEST_FILE.read_text(encoding="utf-8") != test_source:
        TEST_FILE.write_text(test_source, encoding="utf-8")
        changed.append(str(TEST_FILE.relative_to(ROOT)))
    return digest, changed


def apply() -> dict[str, object]:
    variants = _variant_files()
    if not variants:
        html, config_markup, config_js = _load_canonical_authority()
        digest, changed = _write_canonical(html, config_markup, config_js)
        return {
            "status": "repaired" if changed else "noop",
            "reason": "exact-asset semantic overlay verified on canonical frontend",
            "final_html_sha256": digest,
            "rewritten_files": changed,
        }
    if V18_SOURCE not in variants:
        raise RuntimeError("workspace_frontend_v18.py is required as the final patch authority")

    variant_set = {path.resolve() for path in variants}
    external = _external_python_files(variant_set)
    _validate_import_contract(external)

    final_html, config_markup, config_js = _load_authority()
    digest, canonical_changed = _write_canonical(final_html, config_markup, config_js)
    changed_refs = _rewrite_references(external)

    for path in variants:
        path.unlink()

    stale = []
    for path in _external_python_files(set()):
        if path.resolve() == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8")
        if VERSION_REF_RE.search(text):
            stale.append(str(path.relative_to(ROOT)))
    if stale:
        raise RuntimeError("stale workspace frontend generation references remain: " + ", ".join(stale))

    return {
        "status": "applied",
        "final_html_sha256": digest,
        "removed_variants": len(variants),
        "rewritten_files": canonical_changed + [str(path.relative_to(ROOT)) for path in changed_refs],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Consolidate WorkSpace frontend generations into one canonical module")
    parser.add_argument("--apply", action="store_true", help="apply the canonicalization")
    args = parser.parse_args()
    if not args.apply:
        print({"status": "ready", "variants": [p.name for p in _variant_files()]})
        return 0
    print(apply())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

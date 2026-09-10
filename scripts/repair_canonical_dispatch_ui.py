#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSOLIDATOR = ROOT / "scripts" / "consolidate_workspace_frontend.py"

DISPATCH_CSS = r"""
.dispatch-card{width:min(980px,96vw);max-height:90vh;display:flex;flex-direction:column}
.dispatch-body{display:grid;grid-template-columns:minmax(260px,.78fr) minmax(0,1.5fr);gap:14px;padding:14px;overflow:auto}
.dispatch-input-panel,.dispatch-preview{min-width:0}
.dispatch-input-panel textarea{width:100%;min-height:190px;resize:vertical;background:#17181c;color:#eff0f2;border:1px solid #3b3d44;border-radius:12px;padding:12px;line-height:1.5;outline:0}
.dispatch-hint{font-size:11px;line-height:1.45;color:#8e929b;margin:8px 2px 12px}
.dispatch-actions{display:flex;gap:8px;flex-wrap:wrap}.dispatch-actions .soft-btn{min-width:110px}
.dispatch-statusbar{display:flex;align-items:center;gap:8px;min-height:32px;margin-bottom:8px}
.dispatch-badge{display:inline-flex;align-items:center;border:1px solid #3b3d44;border-radius:999px;padding:4px 9px;font-size:10px;color:#c6c9d0;background:#1a1b1f}
.dispatch-badge.ready{color:#a8e6c8;border-color:#285b46;background:#14271f}.dispatch-badge.preview{color:#e9c996;border-color:#5b4828;background:#2a2115}
.dispatch-title{font-size:15px;font-weight:680;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.dispatch-summary{font-size:12px;line-height:1.5;color:#a9adb5;margin:0 0 10px}
.dispatch-diagram{min-height:260px;border:1px solid #30323a;border-radius:14px;background:#111216;overflow:auto;padding:8px}
.dispatch-diagram svg{display:block;width:100%;min-width:520px;height:auto}
.dispatch-code{margin-top:10px}.dispatch-code summary{cursor:pointer;color:#bfc2c8;font-size:12px;padding:6px 2px}
.dispatch-code pre{margin:5px 0 0;max-height:220px;overflow:auto;background:#101115;border:1px solid #30323a;border-radius:10px;padding:10px;color:#bfc4cc;font-size:11px;line-height:1.45;white-space:pre}
.dispatch-progress{font-size:11px;color:#9ca0a9;margin-top:10px;min-height:18px}.dispatch-run-note{font-size:10px;color:#7e828a;margin-top:8px}
@media(max-width:760px){.dispatch-body{grid-template-columns:1fr}.dispatch-card{max-height:94vh}.dispatch-input-panel textarea{min-height:120px}.dispatch-diagram{min-height:210px}}
"""

DISPATCH_MENU = r"""
      <button class="menu-row" type="button" data-action="dispatch">
        <span class="menu-icon purple"><svg viewBox="0 0 24 24"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M8 6h8M7 8l4 8M17 8l-4 8"/></svg></span>
        <span><span class="menu-title">Dispatch workflow</span><span class="menu-sub">Describe → plan → diagram → approve</span></span><span class="menu-state">Local</span>
      </button>
"""

DISPATCH_MODAL = r"""
<div class="library-modal" id="dispatchModal">
  <div class="library-card dispatch-card">
    <div class="library-head">
      <div><h2>WorkSpace Dispatch</h2><div class="dispatch-hint">Describe the result you want. WorkSpace proposes a bounded DAG; deterministic policy decides whether it is valid and executable.</div></div>
      <button class="soft-btn" id="closeDispatch" type="button">Close</button>
    </div>
    <div class="dispatch-body">
      <div class="dispatch-input-panel">
        <textarea id="dispatchDescription" maxlength="12000" placeholder="Describe the outcome, steps, constraints, approvals, and deliverable you want…"></textarea>
        <div class="dispatch-hint">Enterprise-Lean v1: ≤12 nodes · ≤2 conceptual parallel nodes · no loops · one compiler model call · no automatic execution.</div>
        <div class="dispatch-actions"><button class="soft-btn primary" id="compileDispatch" type="button">Create workflow</button><button class="soft-btn" id="clearDispatch" type="button">Clear</button></div>
        <div class="dispatch-progress" id="dispatchProgress"></div>
      </div>
      <div class="dispatch-preview">
        <div class="dispatch-statusbar"><span class="dispatch-badge preview" id="dispatchBadge">No plan</span><div class="dispatch-title" id="dispatchTitle">Describe a workflow to begin</div></div>
        <p class="dispatch-summary" id="dispatchSummary">Validated workflow JSON, Mermaid code and a local SVG diagram will appear here.</p>
        <div class="dispatch-diagram" id="dispatchDiagram"></div>
        <details class="dispatch-code"><summary>Flowchart code · Mermaid</summary><pre id="dispatchMermaid"></pre></details>
        <details class="dispatch-code"><summary>Workflow code · JSON</summary><pre id="dispatchJson"></pre></details>
        <div class="dispatch-actions" style="margin-top:12px"><button class="soft-btn primary" id="runDispatch" type="button" disabled>Approve &amp; Dispatch</button><button class="soft-btn" id="copyMermaid" type="button" disabled>Copy Mermaid</button></div>
        <div class="dispatch-run-note" id="dispatchRunNote">Custom DAGs remain preview-only until an audited execution adapter exists.</div>
      </div>
    </div>
  </div>
</div>
"""

DISPATCH_JS = r"""
state.dispatchDraft=null;state.dispatchPoll=null;
function closeDispatch(){document.getElementById('dispatchModal').classList.remove('open');if(state.dispatchPoll){clearTimeout(state.dispatchPoll);state.dispatchPoll=null}}
function resetDispatchPreview(){state.dispatchDraft=null;const b=document.getElementById('dispatchBadge');b.className='dispatch-badge preview';b.textContent='No plan';document.getElementById('dispatchTitle').textContent='Describe a workflow to begin';document.getElementById('dispatchSummary').textContent='Validated workflow JSON, Mermaid code and a local SVG diagram will appear here.';document.getElementById('dispatchDiagram').replaceChildren();document.getElementById('dispatchMermaid').textContent='';document.getElementById('dispatchJson').textContent='';document.getElementById('runDispatch').disabled=true;document.getElementById('copyMermaid').disabled=true;document.getElementById('dispatchRunNote').textContent='Custom DAGs remain preview-only until an audited execution adapter exists.';document.getElementById('dispatchProgress').textContent=''}
function openDispatch(){document.getElementById('plusMenu').classList.remove('open');const m=document.getElementById('dispatchModal'),a=document.getElementById('dispatchDescription');if(!a.value.trim()&&input.value.trim())a.value=input.value.trim();m.classList.add('open');setTimeout(()=>a.focus(),30)}
function renderDispatchSvg(svg){const host=document.getElementById('dispatchDiagram');host.replaceChildren();if(!svg)return;const parsed=new DOMParser().parseFromString(svg,'image/svg+xml'),root=parsed.documentElement;if(root.tagName.toLowerCase()!=='svg'||parsed.querySelector('parsererror,script,foreignObject,iframe,image,use'))throw new Error('Diagram safety validation failed');for(const el of root.querySelectorAll('*'))for(const attr of [...el.attributes]){const n=attr.name.toLowerCase(),v=attr.value.toLowerCase();if(n.startsWith('on')||n==='href'||n==='xlink:href'||v.includes('javascript:')||v.includes('url(http'))throw new Error('Diagram contains a forbidden external reference')}host.appendChild(document.importNode(root,true))}
function renderDispatchDraft(d){state.dispatchDraft=d;const p=d.plan||{},ready=!!p.execution_ready,b=document.getElementById('dispatchBadge');b.className='dispatch-badge '+(ready?'ready':'preview');b.textContent=ready?'Ready to dispatch':'Preview only';document.getElementById('dispatchTitle').textContent=p.title||'Workflow';document.getElementById('dispatchSummary').textContent=p.summary||'';renderDispatchSvg(p.diagram_svg||'');document.getElementById('dispatchMermaid').textContent=p.mermaid||'';document.getElementById('dispatchJson').textContent=JSON.stringify({schema_version:p.schema_version,title:p.title,summary:p.summary,nodes:p.nodes,waves:p.waves,dispatch_batches:p.dispatch_batches,spec_sha256:p.spec_sha256},null,2);document.getElementById('runDispatch').disabled=!ready;document.getElementById('copyMermaid').disabled=!p.mermaid;document.getElementById('dispatchRunNote').textContent=p.execution_reason||'Explicit approval is required before dispatch.';document.getElementById('dispatchProgress').textContent='Plan validated · '+String((p.nodes||[]).length)+' nodes · max 2 conceptual parallel nodes'}
async function compileDispatch(){const description=document.getElementById('dispatchDescription').value.trim();if(!description){showToast('Describe the workflow first');return}const button=document.getElementById('compileDispatch');button.disabled=true;document.getElementById('dispatchProgress').textContent='Compiling and validating workflow…';try{renderDispatchDraft(await api('/api/dispatch/compile',{method:'POST',body:JSON.stringify({description})}))}catch(err){document.getElementById('dispatchProgress').textContent='Workflow blocked: '+err.message;showToast(err.message)}finally{button.disabled=false}}
async function pollDispatch(){if(!state.dispatchDraft)return;try{const d=await api('/api/dispatch/'+encodeURIComponent(state.dispatchDraft.workflow_id));state.dispatchDraft=d;const s=String(d.status||'unknown');document.getElementById('dispatchProgress').textContent='Dispatch status: '+s;if(s==='completed'){const b=document.getElementById('dispatchBadge');b.textContent='Completed';b.className='dispatch-badge ready';document.getElementById('runDispatch').disabled=true;showToast('Workflow completed');return}if(s==='failed'){const b=document.getElementById('dispatchBadge');b.textContent='Failed';b.className='dispatch-badge preview';document.getElementById('dispatchRunNote').textContent=d.error||'Workflow failed';document.getElementById('runDispatch').disabled=false;return}state.dispatchPoll=setTimeout(pollDispatch,1500)}catch(err){document.getElementById('dispatchProgress').textContent='Status error: '+err.message}}
async function runDispatch(){const d=state.dispatchDraft;if(!d||!d.plan?.execution_ready)return;const button=document.getElementById('runDispatch');button.disabled=true;document.getElementById('dispatchProgress').textContent='Approval recorded · dispatching…';try{state.dispatchDraft=await api('/api/dispatch/'+encodeURIComponent(d.workflow_id)+'/run',{method:'POST',body:JSON.stringify({approved:true,language:document.getElementById('lang').value,output_format:document.getElementById('fmt').value})});state.dispatchPoll=setTimeout(pollDispatch,500)}catch(err){button.disabled=false;document.getElementById('dispatchProgress').textContent='Dispatch blocked: '+err.message;showToast(err.message)}}
async function copyDispatchMermaid(){const text=state.dispatchDraft?.plan?.mermaid||'';if(!text)return;try{await navigator.clipboard.writeText(text);showToast('Mermaid copied')}catch(e){showToast('Clipboard unavailable')}}
document.querySelector('.menu-row[data-action="dispatch"]').onclick=openDispatch;document.getElementById('closeDispatch').onclick=closeDispatch;document.getElementById('compileDispatch').onclick=()=>compileDispatch().catch(e=>showToast(e.message));document.getElementById('clearDispatch').onclick=()=>{document.getElementById('dispatchDescription').value='';resetDispatchPreview()};document.getElementById('runDispatch').onclick=()=>runDispatch().catch(e=>showToast(e.message));document.getElementById('copyMermaid').onclick=()=>copyDispatchMermaid().catch(e=>showToast(e.message));
"""

REQUIRED_MARKERS = (
    'data-action="dispatch"',
    'id="dispatchModal"',
    'id="compileDispatch"',
    'id="runDispatch"',
    "Approve &amp; Dispatch",
    "/api/dispatch/compile",
    "p.diagram_svg",
    "p.mermaid",
    "Preview only",
    "execution_ready",
    "≤12 nodes",
    "≤2 conceptual parallel nodes",
    "DOMParser",
    "foreignObject",
    "Diagram safety validation failed",
)


def _load_consolidator():
    spec = importlib.util.spec_from_file_location("workspace_frontend_consolidator", CONSOLIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load workspace frontend consolidator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _insert_once(source: str, anchor: str, addition: str, label: str) -> str:
    count = source.count(anchor)
    if count != 1:
        raise RuntimeError(f"dispatch repair '{label}' expected exactly one anchor, got {count}")
    return source.replace(anchor, addition + anchor, 1)


def _repair(html: str) -> str:
    if ".dispatch-card{" not in html:
        if html.count("</style>") != 1:
            raise RuntimeError("dispatch CSS requires exactly one </style> boundary")
        html = html.replace("</style>", DISPATCH_CSS + "</style>", 1)

    if 'data-action="dispatch"' not in html:
        html = _insert_once(
            html,
            '      <div class="menu-divider"></div>\n      <div class="menu-options">',
            DISPATCH_MENU,
            "menu",
        )

    if 'id="dispatchModal"' not in html:
        html = _insert_once(
            html,
            '<div class="library-modal" id="libraryModal">',
            DISPATCH_MODAL,
            "modal",
        )

    if "function renderDispatchSvg(svg)" not in html:
        html = _insert_once(
            html,
            "document.getElementById('sidebarToggle').onclick=toggleSidebar;",
            DISPATCH_JS + "\n",
            "runtime",
        )

    missing = [marker for marker in REQUIRED_MARKERS if marker not in html]
    if missing:
        raise RuntimeError("dispatch repair missing markers: " + ", ".join(missing))
    for forbidden in ("mermaid.min.js", "cdn.jsdelivr.net", "unpkg.com"):
        if forbidden in html:
            raise RuntimeError(f"dispatch repair introduced forbidden remote dependency: {forbidden}")
    return html


def main() -> int:
    consolidator = _load_consolidator()
    html, config_markup, config_js = consolidator._load_canonical_authority()
    repaired = _repair(html)
    digest, changed = consolidator._write_canonical(repaired, config_markup, config_js)
    print(json.dumps({
        "status": "repaired" if changed else "noop",
        "final_html_sha256": digest,
        "rewritten_files": changed,
        "required_markers": list(REQUIRED_MARKERS),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v7 import WORKSPACE_HTML_V7


html = WORKSPACE_HTML_V7

workflow_css = r"""
.workflow-studio-btn{position:fixed;right:18px;bottom:18px;z-index:40;border:1px solid #474a52;background:#24262b;color:var(--text);border-radius:999px;padding:10px 15px;font-weight:650;box-shadow:0 8px 28px rgba(0,0,0,.28);cursor:pointer}.workflow-studio-btn:hover{background:#303239}.workflow-studio-overlay{position:fixed;inset:0;z-index:80;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;padding:20px}.workflow-studio-overlay.open{display:flex}.workflow-studio-panel{width:min(1180px,96vw);max-height:92vh;overflow:auto;background:#1d1f23;border:1px solid #41434a;border-radius:16px;padding:18px;box-shadow:0 24px 80px rgba(0,0,0,.48)}.workflow-studio-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.workflow-studio-head h2{font-size:18px;margin:0}.workflow-studio-note{font-size:12px;color:var(--muted);margin:5px 0 14px}.workflow-studio-input{width:100%;min-height:118px;resize:vertical;background:#151619;color:var(--text);border:1px solid #3b3d43;border-radius:10px;padding:12px;font:inherit;box-sizing:border-box}.workflow-studio-actions{display:flex;gap:8px;align-items:center;margin:10px 0 14px;flex-wrap:wrap}.workflow-chip{font-size:11px;border:1px solid #3f4249;border-radius:999px;padding:4px 8px;color:var(--muted)}.workflow-grid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(280px,.65fr);gap:14px}.workflow-card{background:#17181b;border:1px solid #33363c;border-radius:12px;padding:12px;min-width:0}.workflow-card h3{font-size:13px;margin:0 0 9px}.workflow-diagram{overflow:auto;min-height:260px;color:#d8dae0}.workflow-diagram svg{display:block;min-width:520px;max-width:100%;height:auto}.workflow-code{white-space:pre;overflow:auto;max-height:300px;background:#101114;border-radius:8px;padding:10px;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.workflow-step{border-left:2px solid #454851;padding:7px 9px;margin:6px 0}.workflow-step strong{display:block;font-size:12px}.workflow-step span{font-size:11px;color:var(--muted)}.workflow-warning{font-size:11px;color:#d9b45c;margin-top:5px}.workflow-tabs{display:flex;gap:6px;margin-bottom:8px}.workflow-tabs button{font-size:11px}.workflow-hidden{display:none!important}@media(max-width:820px){.workflow-grid{grid-template-columns:1fr}.workflow-studio-panel{padding:14px}.workflow-studio-btn{right:12px;bottom:12px}}
"""
html = _replace_once(
    html,
    "</style>",
    workflow_css + "</style>",
    "workflow-studio-css",
)

workflow_markup = r"""
<button type="button" class="workflow-studio-btn" id="workflowStudioBtn">Workflow Studio</button>
<div class="workflow-studio-overlay" id="workflowStudioOverlay" role="dialog" aria-modal="true" aria-labelledby="workflowStudioTitle">
  <div class="workflow-studio-panel">
    <div class="workflow-studio-head">
      <h2 id="workflowStudioTitle">Workflow Studio</h2>
      <button type="button" class="soft-btn" id="workflowStudioClose">Close</button>
    </div>
    <div class="workflow-studio-note">Describe the process in plain language. WorkSpace compiles a design-only graph; creating a diagram never grants execution authority.</div>
    <textarea class="workflow-studio-input" id="workflowDescription" maxlength="8000" placeholder="Example: Every Monday, collect project metrics, validate them, flag risks, prepare a management report, require manager approval, then publish the approved report."></textarea>
    <div class="workflow-studio-actions">
      <button type="button" class="soft-btn primary" id="workflowCompileBtn">Compile workflow</button>
      <span class="workflow-chip" id="workflowStatus">Design only · no execution</span>
      <span class="workflow-chip" id="workflowRisk">Risk: —</span>
      <span class="workflow-chip" id="workflowDataClass">Data: —</span>
    </div>
    <div class="workflow-grid">
      <div class="workflow-card">
        <h3>Diagram</h3>
        <div class="workflow-diagram" id="workflowDiagram"><div class="library-empty">Describe a workflow and compile it.</div></div>
      </div>
      <div class="workflow-card">
        <h3>Steps</h3>
        <div id="workflowSteps"><div class="library-empty">No workflow compiled.</div></div>
      </div>
      <div class="workflow-card">
        <div class="workflow-tabs">
          <button type="button" class="soft-btn" data-workflow-tab="mermaid">Mermaid</button>
          <button type="button" class="soft-btn" data-workflow-tab="json">Contract JSON</button>
        </div>
        <pre class="workflow-code" id="workflowMermaid"></pre>
        <pre class="workflow-code workflow-hidden" id="workflowJson"></pre>
      </div>
      <div class="workflow-card">
        <h3>Safety / warnings</h3>
        <div id="workflowWarnings"><div class="library-empty">No warnings.</div></div>
      </div>
    </div>
  </div>
</div>
"""
html = _replace_once(
    html,
    "</body>",
    workflow_markup + "</body>",
    "workflow-studio-markup",
)

workflow_js = r"""
(function(){
const overlay=document.getElementById('workflowStudioOverlay'),desc=document.getElementById('workflowDescription'),diagram=document.getElementById('workflowDiagram'),steps=document.getElementById('workflowSteps'),warnings=document.getElementById('workflowWarnings'),mermaid=document.getElementById('workflowMermaid'),json=document.getElementById('workflowJson');
function openWorkflowStudio(){overlay.classList.add('open');desc.focus()}
function closeWorkflowStudio(){overlay.classList.remove('open')}
function textNode(tag,text,cls){const e=document.createElement(tag);if(cls)e.className=cls;e.textContent=text;return e}
function renderWorkflow(d){const c=d.contract||{};document.getElementById('workflowRisk').textContent='Risk: '+(c.risk_level||'—');document.getElementById('workflowDataClass').textContent='Data: '+(c.data_class||'—');document.getElementById('workflowStatus').textContent=d.execution_authorized?'Execution authorized':'Design only · no execution';diagram.innerHTML=d.diagram?.svg||'<div class="library-empty">Diagram unavailable.</div>';steps.innerHTML='';for(const n of c.nodes||[]){const row=document.createElement('div');row.className='workflow-step';row.append(textNode('strong',n.label||n.id),textNode('span',(n.kind||'')+' · '+(n.action||'')+(n.approval_required?' · approval required':'')));steps.append(row)}if(!(c.nodes||[]).length)steps.append(textNode('div','No steps.','library-empty'));warnings.innerHTML='';for(const w of c.warnings||[])warnings.append(textNode('div',w,'workflow-warning'));if(!(c.warnings||[]).length)warnings.append(textNode('div','No warnings.','library-empty'));mermaid.textContent=d.diagram?.mermaid||'';json.textContent=JSON.stringify(c,null,2)}
async function compileWorkflow(){const description=desc.value.trim();if(!description){showToast('Describe the workflow first');return}const btn=document.getElementById('workflowCompileBtn');btn.disabled=true;btn.textContent='Compiling…';try{const d=await api('/api/workflows/compile',{method:'POST',body:JSON.stringify({description,language:'ja'})});renderWorkflow(d);showToast('Workflow compiled — design only')}catch(e){showToast(e.message)}finally{btn.disabled=false;btn.textContent='Compile workflow'}}
document.getElementById('workflowStudioBtn').onclick=openWorkflowStudio;document.getElementById('workflowStudioClose').onclick=closeWorkflowStudio;document.getElementById('workflowCompileBtn').onclick=compileWorkflow;overlay.addEventListener('click',e=>{if(e.target===overlay)closeWorkflowStudio()});for(const b of document.querySelectorAll('[data-workflow-tab]'))b.onclick=()=>{const target=b.dataset.workflowTab;mermaid.classList.toggle('workflow-hidden',target!=='mermaid');json.classList.toggle('workflow-hidden',target!=='json')};
})();
"""
html = _replace_once(
    html,
    "</body>",
    f"<script>{workflow_js}</script></body>",
    "workflow-studio-js",
)

WORKSPACE_HTML_V8 = html

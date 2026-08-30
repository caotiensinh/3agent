from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v8 import WORKSPACE_HTML_V8


html = WORKSPACE_HTML_V8

dispatch_css = r"""
.workflow-dispatch-box{margin-top:12px;padding:11px;border:1px solid #3a3d44;border-radius:10px;background:#131417}.workflow-dispatch-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.workflow-dispatch-detail{font-size:11px;color:var(--muted);margin-top:7px;word-break:break-word}.workflow-dispatch-ok{color:#79c98a}.workflow-dispatch-blocked{color:#e0a060}.workflow-dispatch-danger{border-color:#7c4b4b!important}.workflow-dispatch-danger:hover{background:#4a2727!important}
"""
html = _replace_once(
    html,
    "</style>",
    dispatch_css + "</style>",
    "workflow-dispatch-css",
)

dispatch_markup = r"""
<div class="workflow-dispatch-box" id="workflowDispatchBox">
  <div class="workflow-dispatch-row">
    <button type="button" class="soft-btn" id="workflowPrepareDispatchBtn">Prepare execution</button>
    <button type="button" class="soft-btn workflow-dispatch-danger" id="workflowAuthorizeDispatchBtn" disabled>Authorize &amp; run</button>
    <span class="workflow-chip" id="workflowDispatchStatus">Execution: not prepared</span>
  </div>
  <div class="workflow-dispatch-detail" id="workflowDispatchDetail">Only an administrator can prepare and authorize a bounded V2 execution. Diagram creation itself grants no authority.</div>
</div>
"""
html = _replace_once(
    html,
    '<div class="workflow-grid">',
    dispatch_markup + '<div class="workflow-grid">',
    "workflow-dispatch-markup",
)

dispatch_js = r"""
(function(){
let prepared=null;
const prepareBtn=document.getElementById('workflowPrepareDispatchBtn'),runBtn=document.getElementById('workflowAuthorizeDispatchBtn'),status=document.getElementById('workflowDispatchStatus'),detail=document.getElementById('workflowDispatchDetail'),json=document.getElementById('workflowJson');
function setDispatch(text,cls,extra){status.textContent='Execution: '+text;status.classList.remove('workflow-dispatch-ok','workflow-dispatch-blocked');if(cls)status.classList.add(cls);detail.textContent=extra||''}
function currentContract(){const raw=(json.textContent||'').trim();if(!raw)throw new Error('Compile a workflow before preparing execution');const parsed=JSON.parse(raw);if(!parsed||typeof parsed!=='object')throw new Error('Workflow contract is unavailable');return parsed}
prepareBtn.addEventListener('click',async()=>{prepareBtn.disabled=true;runBtn.disabled=true;prepared=null;setDispatch('checking admission','', 'WorkSpace is compiling the diagram contract into an authoritative execution admission.');try{const d=await api('/api/workflows/prepare-dispatch',{method:'POST',body:JSON.stringify({contract:currentContract(),language:'ja',output_format:'pptx'})});prepared=d;runBtn.disabled=false;setDispatch('prepared','workflow-dispatch-ok','Task '+d.task_id+' · low-risk bounded profile · administrator authorization still required. Fingerprint: '+d.approval_fingerprint)}catch(e){setDispatch('blocked','workflow-dispatch-blocked',e.message);showToast('Execution admission blocked: '+e.message)}finally{prepareBtn.disabled=false}});
runBtn.addEventListener('click',async()=>{if(!prepared){showToast('Prepare execution first');return}const typed=window.prompt('Execution is a side effect. Type AUTHORIZE exactly to run task '+prepared.task_id+'.');if(typed!=='AUTHORIZE'){showToast('Execution not authorized');return}runBtn.disabled=true;prepareBtn.disabled=true;setDispatch('running','', 'Authorized task is running through the existing WorkSpace validator/budget boundary.');try{const d=await api('/api/workflows/'+encodeURIComponent(prepared.task_id)+'/execute',{method:'POST',body:JSON.stringify({approval_fingerprint:prepared.approval_fingerprint,confirmation:'AUTHORIZE'})});setDispatch(d.dispatch_status||'finished','workflow-dispatch-ok','Task '+d.task_id+' finished with runtime status '+(d.result?.status||'unknown')+'.');showToast('Workflow dispatch finished')}catch(e){setDispatch('failed','workflow-dispatch-blocked',e.message);showToast('Workflow dispatch failed: '+e.message)}finally{prepared=null;runBtn.disabled=true;prepareBtn.disabled=false}});
const compileBtn=document.getElementById('workflowCompileBtn');if(compileBtn)compileBtn.addEventListener('click',()=>{prepared=null;runBtn.disabled=true;setDispatch('not prepared','', 'Compile result changed; execution requires a fresh admission and fingerprint.')});
})();
"""
html = _replace_once(
    html,
    "</body>",
    f"<script>{dispatch_js}</script></body>",
    "workflow-dispatch-js",
)

WORKSPACE_HTML_V9 = html

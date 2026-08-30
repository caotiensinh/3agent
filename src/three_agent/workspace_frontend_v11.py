from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v8 import WORKSPACE_HTML_V8


# Start before V2 dispatch JavaScript so there is exactly one execution controller
# in the page. Reapply the current v10 response-language fidelity changes, then add
# the V3 state-machine controls.
html = WORKSPACE_HTML_V8

html = _replace_once(
    html,
    '<label>Response language<select id="lang"><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    '<label>Response language<select id="lang"><option value="auto" selected>Auto · follow current request</option><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    "response-language-auto",
)

html = _replace_once(
    html,
    "JSON.stringify({description,language:'ja'})",
    "JSON.stringify({description,language:document.getElementById('lang').value})",
    "workflow-compile-language",
)

v3_css = r"""
.workflow-v3-box{margin-top:12px;padding:11px;border:1px solid #3a3d44;border-radius:10px;background:#131417}.workflow-v3-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.workflow-v3-detail{font-size:11px;color:var(--muted);margin-top:7px;word-break:break-word}.workflow-v3-ok{color:#79c98a}.workflow-v3-paused{color:#e0b85e}.workflow-v3-blocked{color:#e08a60}.workflow-v3-danger{border-color:#7c4b4b!important}.workflow-v3-danger:hover{background:#4a2727!important}.workflow-v3-input{width:230px;max-width:60vw;background:#151619;color:var(--text);border:1px solid #3b3d43;border-radius:8px;padding:7px 9px;font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.workflow-v3-separator{width:1px;height:24px;background:#36383e;margin:0 2px}@media(max-width:720px){.workflow-v3-separator{display:none}.workflow-v3-input{width:100%;max-width:none}}
"""
html = _replace_once(
    html,
    "</style>",
    v3_css + "</style>",
    "workflow-v3-css",
)

v3_markup = r"""
<div class="workflow-v3-box" id="workflowV3Box">
  <div class="workflow-v3-row">
    <button type="button" class="soft-btn" id="workflowV3PrepareBtn">Prepare V3</button>
    <button type="button" class="soft-btn workflow-v3-danger" id="workflowV3StartBtn" disabled>Authorize &amp; start</button>
    <span class="workflow-v3-separator"></span>
    <input class="workflow-v3-input" id="workflowV3TaskId" placeholder="TASK-YYYYMMDD-0001" aria-label="Workflow task ID">
    <button type="button" class="soft-btn" id="workflowV3LoadBtn">Load state</button>
    <span class="workflow-v3-separator"></span>
    <button type="button" class="soft-btn" id="workflowV3ApproveBtn" disabled>Approve checkpoint</button>
    <button type="button" class="soft-btn workflow-v3-danger" id="workflowV3RejectBtn" disabled>Reject checkpoint</button>
    <span class="workflow-chip" id="workflowV3Status">V3: not prepared</span>
  </div>
  <div class="workflow-v3-detail" id="workflowV3Detail">Manual low-risk workflows may use deterministic validation branches and persistent approval checkpoints. Scheduling, arbitrary conditions, branch joins and new capabilities remain blocked.</div>
</div>
"""
html = _replace_once(
    html,
    '<div class="workflow-grid">',
    v3_markup + '<div class="workflow-grid">',
    "workflow-v3-markup",
)

v3_js = r"""
(function(){
let active=null;
const prepareBtn=document.getElementById('workflowV3PrepareBtn'),startBtn=document.getElementById('workflowV3StartBtn'),loadBtn=document.getElementById('workflowV3LoadBtn'),approveBtn=document.getElementById('workflowV3ApproveBtn'),rejectBtn=document.getElementById('workflowV3RejectBtn'),taskInput=document.getElementById('workflowV3TaskId'),status=document.getElementById('workflowV3Status'),detail=document.getElementById('workflowV3Detail'),json=document.getElementById('workflowJson');
function currentContract(){const raw=(json.textContent||'').trim();if(!raw)throw new Error('Compile a workflow before preparing V3');const parsed=JSON.parse(raw);if(!parsed||typeof parsed!=='object')throw new Error('Workflow contract is unavailable');return parsed}
function resetButtons(){startBtn.disabled=true;approveBtn.disabled=true;rejectBtn.disabled=true}
function setState(text,cls,message){status.textContent='V3: '+text;status.classList.remove('workflow-v3-ok','workflow-v3-paused','workflow-v3-blocked');if(cls)status.classList.add(cls);detail.textContent=message||''}
function applyState(d){active=active||{};active.task_id=d.task_id||active.task_id;taskInput.value=active.task_id||'';active.checkpoint=d.checkpoint||null;resetButtons();if(d.status==='prepared'&&active.approval_fingerprint){startBtn.disabled=false;setState('prepared','workflow-v3-ok','Task '+d.task_id+' is prepared. Initial administrator authorization is still required.')}else if(d.status==='paused'&&d.checkpoint){approveBtn.disabled=false;rejectBtn.disabled=false;setState('paused at '+d.checkpoint.node_id,'workflow-v3-paused','Checkpoint: '+(d.checkpoint.label||d.checkpoint.node_id)+' · revision '+(d.revision||'—')+' · choose APPROVE or REJECT.')}else if(d.status==='completed'){setState('completed','workflow-v3-ok','Task '+d.task_id+' completed with required validators passed.')}else if(d.status==='rejected'){setState('rejected','workflow-v3-blocked','Task '+d.task_id+' stopped on the rejected approval branch.')}else if(d.status==='blocked'||d.status==='failed'){setState(d.status,'workflow-v3-blocked',(d.terminal_reason||'runtime gate')+(d.error?' · '+d.error:''));}else{setState(d.status||'unknown','', 'Task '+(d.task_id||'')+' · current node '+(d.current_node||'—'));}}
prepareBtn.addEventListener('click',async()=>{prepareBtn.disabled=true;resetButtons();active=null;setState('checking admission','', 'Compiling the diagram contract into a bounded V3 state machine.');try{const d=await api('/api/workflows/prepare-dispatch',{method:'POST',body:JSON.stringify({contract:currentContract(),language:document.getElementById('lang').value,output_format:'pptx'})});active={task_id:d.task_id,approval_fingerprint:d.approval_fingerprint,checkpoint:null};taskInput.value=d.task_id;applyState(d);showToast('V3 prepared — execution is still unauthorized')}catch(e){setState('blocked','workflow-v3-blocked',e.message);showToast('V3 admission blocked: '+e.message)}finally{prepareBtn.disabled=false}});
startBtn.addEventListener('click',async()=>{if(!active||!active.approval_fingerprint){showToast('Prepare V3 first');return}const typed=window.prompt('Execution is a side effect. Type AUTHORIZE exactly to start '+active.task_id+'.');if(typed!=='AUTHORIZE'){showToast('Execution not authorized');return}resetButtons();prepareBtn.disabled=true;setState('running','', 'Running until completion or the next persistent approval checkpoint.');try{const d=await api('/api/workflows/'+encodeURIComponent(active.task_id)+'/execute',{method:'POST',body:JSON.stringify({approval_fingerprint:active.approval_fingerprint,confirmation:'AUTHORIZE'})});active.approval_fingerprint=null;applyState(d);showToast(d.status==='paused'?'Workflow paused for approval':'Workflow state: '+d.status)}catch(e){setState('failed','workflow-v3-blocked',e.message);showToast('V3 start failed: '+e.message)}finally{prepareBtn.disabled=false}});
loadBtn.addEventListener('click',async()=>{const taskId=(taskInput.value||'').trim();if(!taskId){showToast('Enter a task ID');return}resetButtons();try{const d=await api('/api/workflows/'+encodeURIComponent(taskId)+'/state');active={task_id:taskId,approval_fingerprint:null,checkpoint:d.checkpoint||null};applyState(d);showToast('Workflow state loaded')}catch(e){setState('load failed','workflow-v3-blocked',e.message);showToast('Cannot load workflow state: '+e.message)}});
async function decide(decision){if(!active||!active.checkpoint){showToast('Load a paused checkpoint first');return}const typed=window.prompt('Type '+decision+' exactly for checkpoint '+active.checkpoint.node_id+'.');if(typed!==decision){showToast('Checkpoint decision cancelled');return}resetButtons();setState('resuming','', decision+' accepted locally; server is verifying the exact checkpoint fingerprint.');try{const d=await api('/api/workflows/'+encodeURIComponent(active.task_id)+'/checkpoint',{method:'POST',body:JSON.stringify({checkpoint_fingerprint:active.checkpoint.fingerprint,decision:decision,confirmation:decision})});applyState(d);showToast('Checkpoint decision recorded: '+decision)}catch(e){setState('checkpoint failed','workflow-v3-blocked',e.message);showToast('Checkpoint transition failed: '+e.message)}}
approveBtn.addEventListener('click',()=>decide('APPROVE'));rejectBtn.addEventListener('click',()=>decide('REJECT'));
const compileBtn=document.getElementById('workflowCompileBtn');if(compileBtn)compileBtn.addEventListener('click',()=>{active=null;resetButtons();setState('not prepared','', 'Compile result changed; V3 requires a fresh admission and fingerprint. Existing paused tasks remain recoverable by Task ID.')});
})();
"""
html = _replace_once(
    html,
    "</body>",
    f"<script>{v3_js}</script></body>",
    "workflow-v3-js",
)

WORKSPACE_HTML_V11 = html

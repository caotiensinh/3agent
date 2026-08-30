from __future__ import annotations

from .version import DISPLAY_VERSION
from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v11 import WORKSPACE_HTML_V11


# V4 keeps the hardened V3 authorization/checkpoint controls and changes only the
# release label plus the admitted execution capability description. Endpoints stay
# stable so users do not need a new operational workflow for the new release line.
html = WORKSPACE_HTML_V11
html = html.replace("workflowV3", "workflowV4")
html = html.replace("workflow-v3", "workflow-v4")
html = html.replace("Workflow V3", "Workflow V4")
html = html.replace("Prepare V3", "Prepare V4")
html = html.replace("V3 prepared", "V4 prepared")
html = html.replace("Prepare V4 first", "Prepare V4 first")
html = html.replace("V3 admission blocked", "V4 admission blocked")
html = html.replace("V3 start failed", "V4 start failed")
html = html.replace(
    "Manual low-risk workflows may use deterministic validation branches and persistent approval checkpoints. Scheduling, arbitrary conditions, branch joins and new capabilities remain blocked.",
    "Manual low-risk workflows may use deterministic validation branches, persistent approval checkpoints, and one bounded two-lane parallel DAG (Research → Presentation per lane) with a verified join. Scheduling, event triggers, arbitrary conditions, nested parallelism and new capabilities remain blocked.",
)
html = html.replace(
    "Compiling the diagram contract into a bounded V3 state machine.",
    "Compiling the diagram contract into the bounded V4 state machine.",
)
html = html.replace(
    "V3 requires a fresh admission and fingerprint.",
    "V4 requires a fresh admission and fingerprint.",
)
html = html.replace("status.textContent='V3: '+text", f"status.textContent='{DISPLAY_VERSION} · V4: '+text")
html = html.replace(">V3: not prepared<", f">{DISPLAY_VERSION} · V4: not prepared<")

# Ordinary source chat is a single WorkSpace interaction. Research/Presentation/
# Human Report cards are workflow UI and must never be pre-seeded or re-rendered
# for the default chat path. Explicit research/artifact workflows retain stages.
html = _replace_once(
    html,
    "function addMessage(who,text,cls='',job=null){hideEmpty();const d=document.createElement('div');d.className='msg '+cls;const h=document.createElement('div');h.className='who';h.textContent=who;d.appendChild(h);if(job&&job.stages)d.appendChild(renderStages(job.stages));const b=document.createElement('div');b.className='bubble';if(cls.includes('user'))b.textContent=text;else b.appendChild(renderReport(text));d.appendChild(b);d.dataset.answer=job&&job.answer?job.answer:text;if(job){renderActions(d,job);if(job.artifacts&&job.artifacts.length)d.appendChild(renderArtifacts(job.artifacts))}messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}",
    "function addMessage(who,text,cls='',job=null){hideEmpty();const d=document.createElement('div');d.className='msg '+cls;d.dataset.uiRoute=job&&job.ui_route?job.ui_route:'';const h=document.createElement('div');h.className='who';h.textContent=who;d.appendChild(h);if(job&&job.stages&&job.stages.length&&d.dataset.uiRoute!=='direct_chat')d.appendChild(renderStages(job.stages));const b=document.createElement('div');b.className='bubble';if(cls.includes('user'))b.textContent=text;else b.appendChild(renderReport(text));d.appendChild(b);d.dataset.answer=job&&job.answer?job.answer:text;if(job){renderActions(d,job);if(job.artifacts&&job.artifacts.length)d.appendChild(renderArtifacts(job.artifacts))}messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}",
    "ordinary-chat-add-message",
)
html = _replace_once(
    html,
    "function updateNode(node,j){const old=node.querySelector('.stages');if(old)old.remove();if(j.stages)node.insertBefore(renderStages(j.stages),node.querySelector('.bubble'));const text=(j.status==='queued'||j.status==='running')?'WorkSpace is working…':(j.answer||(j.error||j.status));const b=node.querySelector('.bubble');b.innerHTML='';b.appendChild(renderReport(text));node.dataset.answer=j.answer||'';for(const e of Array.from(node.querySelectorAll('.answerTools,.downloads,.tech')))e.remove();if(j.answer)renderActions(node,j);if(j.artifacts&&j.artifacts.length)node.appendChild(renderArtifacts(j.artifacts));node.classList.toggle('error',j.status==='failed'&&!j.answer)}",
    "function updateNode(node,j){const old=node.querySelector('.stages');if(old)old.remove();if(j.stages&&j.stages.length&&node.dataset.uiRoute!=='direct_chat')node.insertBefore(renderStages(j.stages),node.querySelector('.bubble'));const text=(j.status==='queued'||j.status==='running')?'WorkSpace is working…':(j.answer||(j.error||j.status));const b=node.querySelector('.bubble');b.innerHTML='';b.appendChild(renderReport(text));node.dataset.answer=j.answer||'';for(const e of Array.from(node.querySelectorAll('.answerTools,.downloads,.tech')))e.remove();if(j.answer)renderActions(node,j);if(j.artifacts&&j.artifacts.length)node.appendChild(renderArtifacts(j.artifacts));node.classList.toggle('error',j.status==='failed'&&!j.answer)}",
    "ordinary-chat-update-node",
)
html = _replace_once(
    html,
    "const pending=addMessage('WorkSpace',files.length?'Uploading and validating files…':'Queued…','',{answer:'',stages:[{label:'Research',status:'queued'},{label:'Presentation',status:'queued'},{label:'Human Report',status:'queued'}],artifacts:[]});",
    "const directUi=state.requestMode==='chat'&&document.getElementById('fmt').value==='source';const pending=addMessage('WorkSpace',files.length?'Uploading and validating files…':'Queued…','',{answer:'',ui_route:directUi?'direct_chat':'workflow',stages:directUi?[]:[{label:'Research',status:'queued'},{label:'Presentation',status:'queued'},{label:'Human Report',status:'queued'}],artifacts:[]});",
    "ordinary-chat-pending-stages",
)

WORKSPACE_HTML_V12 = html

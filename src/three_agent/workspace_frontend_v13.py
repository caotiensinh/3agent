from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v12 import WORKSPACE_HTML_V12


html = WORKSPACE_HTML_V12

# Language is authoritative per current request. Keep a hidden `auto` control only
# because workflow-studio JavaScript shares the same request payload field. There
# is no session-level language picker in the user-facing tools menu anymore.
html = _replace_once(
    html,
    '<label>Response language<select id="lang"><option value="auto" selected>Auto · follow current request</option><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    '<select id="lang" hidden aria-hidden="true"><option value="auto" selected>Auto</option></select>',
    "hide-session-language-selector",
)

# Add connector discovery rows at the stable menu boundary. Existing upload,
# library, image, web, deep-research, and GitHub rows remain unchanged. Runtime
# capability metadata is authoritative: discovery rows have zero authority until
# a compatible connector is explicitly configured server-side.
integration_rows = r'''
      <button class="menu-row" type="button" data-action="figma" data-connect-action="true" role="menuitem">
        <span class="menu-icon white">F</span>
        <span><div class="menu-title">Figma</div><div class="menu-sub">Design-to-code workflows</div></span><span class="menu-state">Connect</span>
      </button>
      <button class="menu-row" type="button" data-action="canva" data-connect-action="true" role="menuitem">
        <span class="menu-icon blue">C</span>
        <span><div class="menu-title">Canva</div><div class="menu-sub">Create, review, and edit designs</div></span><span class="menu-state">Connect</span>
      </button>
      <button class="menu-row" type="button" data-action="gmail" data-connect-action="true" role="menuitem">
        <span class="menu-icon white">M</span>
        <span><div class="menu-title">Gmail</div><div class="menu-sub">Read and manage Gmail</div></span><span class="menu-state">Connect</span>
      </button>
'''
html = _replace_once(
    html,
    '      <div class="menu-divider"></div>\n      <div class="menu-options">',
    integration_rows + '      <div class="menu-divider"></div>\n      <div class="menu-options">',
    "integration-menu-boundary",
)

# Completed assistant answers are intentionally quiet: a compact WorkSpace mark
# identifies the speaker and action icons sit below the answer. Workflow stage
# cards are reserved for running or exceptional states, not repeated success text.
compact_answer_css = r'''
.who.workspace-who{height:27px;margin:0 0 5px 4px;display:flex;align-items:center;color:#dfe4ff}
.workspace-message-mark{width:26px;height:26px;display:grid;place-items:center}
.workspace-message-mark svg{width:23px;height:23px}
.answerTools.compact-actions{display:flex;align-items:center;gap:2px;margin:8px 0 0 2px;position:relative}
.answerTools.compact-actions .answerToolButton{width:34px;height:34px;padding:0;border:0;background:transparent;border-radius:9px;display:grid;place-items:center;color:#a9acb3;cursor:pointer}
.answerTools.compact-actions .answerToolButton:hover,.answerTools.compact-actions .answerToolButton:focus-visible{background:#202226;color:#f1f2f4;outline:0}
.answerTools.compact-actions .answerToolButton svg{width:20px;height:20px}
.answerMoreWrap{position:relative;display:flex}
.answerMoreMenu{position:absolute;left:0;bottom:38px;width:180px;padding:6px;background:#202125;border:1px solid #3a3c43;border-radius:12px;box-shadow:var(--shadow);z-index:12}
.answerMoreMenu button{width:100%;height:36px;border:0;background:transparent;border-radius:8px;text-align:left;padding:0 10px;color:#e7e8eb;cursor:pointer;font-size:12px}
.answerMoreMenu button:hover,.answerMoreMenu button:focus-visible{background:#2b2c31;outline:0}
'''
html = _replace_once(
    html,
    "\n</style>",
    compact_answer_css + "\n</style>",
    "compact-answer-actions-css",
)

legacy_render_actions = "function renderActions(node,job){if(!job||!job.answer)return;const bar=document.createElement('div');bar.className='answerTools';const b=document.createElement('button');b.textContent='Copy answer';b.onclick=()=>copyAnswer(node);bar.appendChild(b);node.appendChild(bar)}"
compact_render_actions = r'''function workspaceSenderMark(){const h=document.createElement('div');h.className='who workspace-who';h.title='WorkSpace';h.setAttribute('aria-label','WorkSpace');h.innerHTML='<span class="workspace-message-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 2.8 19.2 7v10L12 21.2 4.8 17V7z"/><path d="m8.2 9.2 3.8-2.1 3.8 2.1v5.6L12 16.9l-3.8-2.1z"/></svg></span>';return h}
function shouldShowAnswerStages(job,route){if(!job||!job.stages||!job.stages.length)return false;const exceptional=job.stages.some(s=>['failed','blocked','waiting_human','waiting-human'].includes(String(s.status||'').toLowerCase()));if(exceptional)return true;const status=String(job.status||'').toLowerCase();if(['failed','blocked','waiting_human','waiting-human'].includes(status))return true;if(job.answer)return false;return route!=='direct_chat'}
function answerToolButton(label,icon,handler){const b=document.createElement('button');b.type='button';b.className='answerToolButton';b.title=label;b.setAttribute('aria-label',label);b.innerHTML=icon;b.onclick=handler;return b}
function exportAnswer(node){const text=node.dataset.answer||'';if(!text)return;const blob=new Blob([text],{type:'text/plain;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='workspace-answer-'+new Date().toISOString().slice(0,10)+'.txt';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),0);showToast('Exported locally')}
function previousUserPrompt(node){let prev=node.previousElementSibling;while(prev){if(prev.classList&&prev.classList.contains('user'))return prev.dataset.answer||'';prev=prev.previousElementSibling}return ''}
async function regenerateAnswer(node){if(document.getElementById('sendBtn').disabled){showToast('WorkSpace is already working');return}const prompt=previousUserPrompt(node);if(!prompt){showToast('Original prompt unavailable');return}const marker='\n\nAttached:';const at=prompt.indexOf(marker);input.value=at>=0?prompt.slice(0,at):prompt;input.dispatchEvent(new Event('input',{bubbles:true}));input.focus();if(at>=0){showToast('Reattach files before regenerating');return}await sendMsg()}
function answerMoreItem(label,handler){const b=document.createElement('button');b.type='button';b.textContent=label;b.onclick=handler;return b}
function renderActions(node,job){const answer=(job&&job.answer)||node.dataset.answer||'';if(!answer)return;const bar=document.createElement('div');bar.className='answerTools compact-actions';const copyIcon='<svg viewBox="0 0 24 24"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>';const exportIcon='<svg viewBox="0 0 24 24"><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M5 14v5h14v-5"/></svg>';const retryIcon='<svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 1 0 1 4"/><path d="M20 4v7h-7"/></svg>';const moreIcon='<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.6" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1.6" fill="currentColor" stroke="none"/></svg>';bar.appendChild(answerToolButton('Copy answer',copyIcon,()=>copyAnswer(node)));bar.appendChild(answerToolButton('Export answer',exportIcon,()=>exportAnswer(node)));bar.appendChild(answerToolButton('Regenerate answer',retryIcon,()=>regenerateAnswer(node)));const wrap=document.createElement('span');wrap.className='answerMoreWrap';const menu=document.createElement('div');menu.className='answerMoreMenu';menu.hidden=true;menu.appendChild(answerMoreItem('Copy answer',()=>{menu.hidden=true;copyAnswer(node)}));menu.appendChild(answerMoreItem('Export .txt',()=>{menu.hidden=true;exportAnswer(node)}));menu.appendChild(answerMoreItem('Regenerate',()=>{menu.hidden=true;regenerateAnswer(node)}));const more=answerToolButton('More answer actions',moreIcon,()=>{menu.hidden=!menu.hidden});more.setAttribute('aria-haspopup','menu');wrap.append(more,menu);bar.appendChild(wrap);node.appendChild(bar)}'''
html = _replace_once(
    html,
    legacy_render_actions,
    compact_render_actions,
    "compact-answer-action-buttons",
)

legacy_add_message = "function addMessage(who,text,cls='',job=null){hideEmpty();const d=document.createElement('div');d.className='msg '+cls;d.dataset.uiRoute=job&&job.ui_route?job.ui_route:'';const h=document.createElement('div');h.className='who';h.textContent=who;d.appendChild(h);if(job&&job.stages&&job.stages.length&&d.dataset.uiRoute!=='direct_chat')d.appendChild(renderStages(job.stages));const b=document.createElement('div');b.className='bubble';if(cls.includes('user'))b.textContent=text;else b.appendChild(renderReport(text));d.appendChild(b);d.dataset.answer=job&&job.answer?job.answer:text;if(job){renderActions(d,job);if(job.artifacts&&job.artifacts.length)d.appendChild(renderArtifacts(job.artifacts))}messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}"
compact_add_message = "function addMessage(who,text,cls='',job=null){hideEmpty();const d=document.createElement('div');d.className='msg '+cls;d.dataset.uiRoute=job&&job.ui_route?job.ui_route:'';let h;if(cls.includes('user')){h=document.createElement('div');h.className='who';h.textContent=who}else h=workspaceSenderMark();d.appendChild(h);if(shouldShowAnswerStages(job,d.dataset.uiRoute))d.appendChild(renderStages(job.stages));const b=document.createElement('div');b.className='bubble';if(cls.includes('user'))b.textContent=text;else b.appendChild(renderReport(text));d.appendChild(b);d.dataset.answer=job&&job.answer?job.answer:text;if(!cls.includes('user')&&d.dataset.answer)renderActions(d,job||{answer:d.dataset.answer});if(job&&job.artifacts&&job.artifacts.length)d.appendChild(renderArtifacts(job.artifacts));messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}"
html = _replace_once(
    html,
    legacy_add_message,
    compact_add_message,
    "compact-assistant-sender-and-history-actions",
)

legacy_update_node = "function updateNode(node,j){const old=node.querySelector('.stages');if(old)old.remove();if(j.stages&&j.stages.length&&node.dataset.uiRoute!=='direct_chat')node.insertBefore(renderStages(j.stages),node.querySelector('.bubble'));const text=(j.status==='queued'||j.status==='running')?'WorkSpace is working…':(j.answer||(j.error||j.status));const b=node.querySelector('.bubble');b.innerHTML='';b.appendChild(renderReport(text));node.dataset.answer=j.answer||'';for(const e of Array.from(node.querySelectorAll('.answerTools,.downloads,.tech')))e.remove();if(j.answer)renderActions(node,j);if(j.artifacts&&j.artifacts.length)node.appendChild(renderArtifacts(j.artifacts));node.classList.toggle('error',j.status==='failed'&&!j.answer)}"
compact_update_node = "function updateNode(node,j){if(j.ui_route)node.dataset.uiRoute=j.ui_route;const old=node.querySelector('.stages');if(old)old.remove();if(shouldShowAnswerStages(j,node.dataset.uiRoute))node.insertBefore(renderStages(j.stages),node.querySelector('.bubble'));const text=(j.status==='queued'||j.status==='running')?'WorkSpace is working…':(j.answer||(j.error||j.status));const b=node.querySelector('.bubble');b.innerHTML='';b.appendChild(renderReport(text));node.dataset.answer=j.answer||'';for(const e of Array.from(node.querySelectorAll('.answerTools,.downloads,.tech')))e.remove();if(j.answer)renderActions(node,j);if(j.artifacts&&j.artifacts.length)node.appendChild(renderArtifacts(j.artifacts));node.classList.toggle('error',j.status==='failed'&&!j.answer)}"
html = _replace_once(
    html,
    legacy_update_node,
    compact_update_node,
    "compact-completed-status-and-actions",
)

WORKSPACE_HTML_V13 = html

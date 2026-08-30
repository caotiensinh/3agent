from __future__ import annotations

from .workspace_frontend_v3 import WORKSPACE_HTML_V3, _replace_once


html = WORKSPACE_HTML_V3

conversation_css = r"""
.conversation-more-btn{width:28px;height:28px;border:0;background:transparent;border-radius:8px;display:grid;place-items:center;cursor:pointer;color:#9a9da4;opacity:0;flex:0 0 auto}.conversation-row:hover .conversation-more-btn,.conversation-row.active .conversation-more-btn{opacity:1}.conversation-more-btn:hover{background:#26272b}.conversation-more-btn svg{width:17px;height:17px}.side-action.selected{background:#17181b;color:#fff}.history-time-heading{font-size:11px;font-weight:650;color:#73767d;padding:9px 10px 4px}.archive-indicator{font-size:9px;color:#858992;border:1px solid #353840;border-radius:999px;padding:1px 5px;flex:0 0 auto}.conversation-menu{position:fixed;width:190px;background:#202125;border:1px solid #3a3c43;border-radius:13px;padding:6px;box-shadow:var(--shadow);display:none;z-index:60}.conversation-menu.open{display:block}.conversation-menu button{width:100%;height:38px;border:0;background:transparent;border-radius:8px;text-align:left;padding:0 10px;cursor:pointer}.conversation-menu button:hover{background:#2b2c31}.conversation-menu button.danger{color:#ffaaaa}.conversation-menu button.danger:hover{background:#382126}.conversation-dialog{width:min(460px,96vw)}.conversation-dialog-body{padding:16px}.conversation-dialog-body input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:10px;padding:10px 11px;outline:0}.conversation-dialog-copy{color:#b4b6bc;margin:0 0 14px}.dialog-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}.soft-btn.danger{background:#8a343a;border-color:#9b4349;color:#fff}.soft-btn.danger:hover{background:#9b3c43}#input:disabled{opacity:.58;cursor:not-allowed}
"""
html = _replace_once(html, "</style>", conversation_css + "</style>", "conversation-css")

search_button = r'''    <button class="side-action" id="historySearchBtn" type="button">
      <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
      <span>Search chats</span>
    </button>'''
archived_button = search_button + r'''
    <button class="side-action" id="archivedChatsBtn" type="button">
      <svg viewBox="0 0 24 24"><path d="M4 7h16v13H4z"/><path d="M3 4h18v3H3zM9 11h6"/></svg>
      <span>Archived chats</span>
    </button>'''
html = _replace_once(html, search_button, archived_button, "archived-nav")

conversation_dialogs = r'''
<div class="conversation-menu" id="conversationMenu">
  <button type="button" id="conversationRenameAction">Rename</button>
  <button type="button" id="conversationPinAction">Pin</button>
  <button type="button" id="conversationArchiveAction">Archive</button>
  <button type="button" class="danger" id="conversationDeleteAction">Delete</button>
</div>
<div class="library-modal" id="renameConversationModal">
  <div class="library-card conversation-dialog">
    <div class="library-head"><h2>Rename chat</h2><button class="soft-btn" id="closeRenameConversation" type="button">Close</button></div>
    <form class="conversation-dialog-body" id="renameConversationForm">
      <input id="renameConversationInput" autocomplete="off" maxlength="96" placeholder="Conversation title" required>
      <div class="dialog-actions"><button class="soft-btn" id="cancelRenameConversation" type="button">Cancel</button><button class="soft-btn primary" type="submit">Save</button></div>
    </form>
  </div>
</div>
<div class="library-modal" id="deleteConversationModal">
  <div class="library-card conversation-dialog">
    <div class="library-head"><h2>Delete chat?</h2><button class="soft-btn" id="closeDeleteConversation" type="button">Close</button></div>
    <div class="conversation-dialog-body">
      <p class="conversation-dialog-copy" id="deleteConversationCopy">This permanently deletes the selected conversation and its saved messages.</p>
      <div class="dialog-actions"><button class="soft-btn" id="cancelDeleteConversation" type="button">Cancel</button><button class="soft-btn danger" id="confirmDeleteConversation" type="button">Delete</button></div>
    </div>
  </div>
</div>
'''
html = _replace_once(
    html,
    '<div class="library-modal" id="libraryModal">',
    conversation_dialogs + '<div class="library-modal" id="libraryModal">',
    "conversation-dialogs",
)

conversation_js = r'''
state.historyView='active';
state.menuConversationId=null;
state.currentConversationArchived=false;

function conversationById(id){return state.conversations.find(item=>item.conversation_id===id)||null}
function closeConversationMenu(){document.getElementById('conversationMenu').classList.remove('open');state.menuConversationId=null}
function closeRenameConversation(){document.getElementById('renameConversationModal').classList.remove('open')}
function closeDeleteConversation(){document.getElementById('deleteConversationModal').classList.remove('open')}
function syncArchiveNav(){const b=document.getElementById('archivedChatsBtn');b.classList.toggle('selected',state.historyView==='archived');b.title=state.historyView==='archived'?'Back to active chats':'View archived chats'}
function syncArchivedComposer(){input.disabled=!!state.currentConversationArchived;document.getElementById('sendBtn').disabled=!!state.currentConversationArchived;input.placeholder=state.currentConversationArchived?'Restore this chat to continue':'Ask WorkSpace'}
function dateBucket(value){const d=new Date(value);if(Number.isNaN(d.getTime()))return 'Older';const now=new Date(),day=new Date(d),today=new Date(now);day.setHours(0,0,0,0);today.setHours(0,0,0,0);const diff=Math.round((today-day)/86400000);if(diff<=0)return 'Today';if(diff===1)return 'Yesterday';if(diff<=7)return 'Previous 7 days';return 'Older'}
function appendTimeGroups(container,items){const order=['Today','Yesterday','Previous 7 days','Older'],groups=new Map(order.map(k=>[k,[]]));for(const item of items)(groups.get(dateBucket(item.updated_at))||groups.get('Older')).push(item);for(const key of order){const rows=groups.get(key);if(!rows.length)continue;const h=document.createElement('div');h.className='history-time-heading';h.textContent=key;container.appendChild(h);for(const item of rows)container.appendChild(buildConversationRow(item))}}
function buildConversationRow(item){const row=document.createElement('div');row.className='conversation-row'+(item.conversation_id===state.currentConversationId?' active':'');row.dataset.id=item.conversation_id;const icon=document.createElement('span');icon.className='conversation-icon';icon.innerHTML=svgChat();const title=document.createElement('span');title.className='conversation-title';title.textContent=item.title;title.title=item.title;row.append(icon,title);if(item.archived){const archived=document.createElement('span');archived.className='archive-indicator';archived.textContent='Archived';row.appendChild(archived)}const more=document.createElement('button');more.type='button';more.className='conversation-more-btn';more.setAttribute('aria-label','Conversation actions');more.innerHTML='<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>';more.onclick=e=>{e.stopPropagation();openConversationMenu(item.conversation_id,more)};row.appendChild(more);row.onclick=()=>openConversation(item.conversation_id);return row}
function renderHistoryList(){const pinned=document.getElementById('pinnedList'),history=document.getElementById('historyList'),section=document.getElementById('pinnedSection');pinned.innerHTML='';history.innerHTML='';syncArchiveNav();if(state.searchQuery){section.classList.add('hidden');document.getElementById('historyHeading').textContent='Search results';for(const item of state.conversations)history.appendChild(buildConversationRow(item))}else if(state.historyView==='archived'){section.classList.add('hidden');document.getElementById('historyHeading').textContent='Archived';appendTimeGroups(history,state.conversations)}else{const p=state.conversations.filter(x=>x.pinned&&!x.archived),normal=state.conversations.filter(x=>!x.pinned&&!x.archived);section.classList.toggle('hidden',p.length===0);document.getElementById('historyHeading').textContent='Chats';for(const item of p)pinned.appendChild(buildConversationRow(item));appendTimeGroups(history,normal)}if(!state.conversations.length){const e=document.createElement('div');e.className='history-empty';e.textContent=state.searchQuery?'No matching chats':(state.historyView==='archived'?'No archived chats':'No saved chats yet');history.appendChild(e)}}
async function loadConversations(query=state.searchQuery){state.searchQuery=String(query||'').trim();const params=new URLSearchParams();if(state.searchQuery){params.set('q',state.searchQuery);params.set('view','all')}else params.set('view',state.historyView);const d=await api('/api/conversations?'+params.toString());state.conversations=d.conversations||[];renderHistoryList()}
async function openConversation(id){const d=await api('/api/conversations/'+encodeURIComponent(id));state.currentConversationId=d.conversation_id;state.currentConversationArchived=!!d.archived;localStorage.setItem('workspace.currentConversationId',d.conversation_id);document.getElementById('conversationName').textContent=(d.title||'Chat')+(d.archived?' · Archived':'');messages.innerHTML='';for(const m of d.messages||[]){if(m.role==='user')addMessage('You',m.content,'user');else addMessage('WorkSpace',m.content,m.status==='failed'?'error':'')}if(!(d.messages||[]).length)showEmpty();syncArchivedComposer();renderHistoryList();if(window.innerWidth<=760)setSidebarCollapsed(true)}
function newChat(){state.currentConversationId=null;state.currentConversationArchived=false;localStorage.removeItem('workspace.currentConversationId');document.getElementById('conversationName').textContent='New chat';messages.innerHTML='';showEmpty();syncArchivedComposer();if(state.historyView!=='active'){state.historyView='active';state.searchQuery='';const q=document.getElementById('historySearchInput');if(q)q.value='';loadConversations('').catch(()=>{})}else renderHistoryList();input.focus();if(window.innerWidth<=760)setSidebarCollapsed(true)}
function openSearch(){if(state.sidebarCollapsed)setSidebarCollapsed(false);const box=document.getElementById('historySearchBox');box.classList.remove('hidden');setTimeout(()=>document.getElementById('historySearchInput').focus(),40)}
function closeSearch(){state.searchQuery='';const inputEl=document.getElementById('historySearchInput');inputEl.value='';document.getElementById('historySearchBox').classList.add('hidden');loadConversations('').catch(()=>{})}
async function toggleArchivedView(){state.searchQuery='';const q=document.getElementById('historySearchInput');if(q)q.value='';document.getElementById('historySearchBox').classList.add('hidden');state.historyView=state.historyView==='archived'?'active':'archived';await loadConversations('')}
function openConversationMenu(id,button){const item=conversationById(id);if(!item)return;state.menuConversationId=id;const menu=document.getElementById('conversationMenu'),pin=document.getElementById('conversationPinAction'),archive=document.getElementById('conversationArchiveAction');pin.textContent=item.pinned?'Unpin':'Pin';pin.classList.toggle('hidden',!!item.archived);archive.textContent=item.archived?'Restore':'Archive';const r=button.getBoundingClientRect();menu.classList.add('open');const width=190,height=158;menu.style.left=Math.max(8,Math.min(r.right-width,window.innerWidth-width-8))+'px';menu.style.top=Math.max(8,Math.min(r.bottom+4,window.innerHeight-height-8))+'px'}
function beginRenameConversation(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();state.menuConversationId=item.conversation_id;const inputEl=document.getElementById('renameConversationInput');inputEl.value=item.title||'';document.getElementById('renameConversationModal').classList.add('open');setTimeout(()=>{inputEl.focus();inputEl.select()},30)}
async function submitRenameConversation(e){e.preventDefault();const id=state.menuConversationId,title=document.getElementById('renameConversationInput').value.trim();if(!id)return;try{const d=await api('/api/conversations/'+encodeURIComponent(id)+'/rename',{method:'POST',body:JSON.stringify({title})});closeRenameConversation();if(state.currentConversationId===id)document.getElementById('conversationName').textContent=d.title+(d.archived?' · Archived':'');showToast('Chat renamed');await loadConversations()}catch(err){showToast(err.message)}}
async function toggleConversationPin(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();await setPinned(item.conversation_id,!item.pinned)}
async function toggleConversationArchive(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();try{await api('/api/conversations/'+encodeURIComponent(item.conversation_id)+'/archive',{method:'POST',body:JSON.stringify({archived:!item.archived})});if(state.currentConversationId===item.conversation_id){state.currentConversationId=null;state.currentConversationArchived=false;localStorage.removeItem('workspace.currentConversationId');document.getElementById('conversationName').textContent='New chat';messages.innerHTML='';showEmpty();syncArchivedComposer()}showToast(item.archived?'Chat restored':'Chat archived');await loadConversations()}catch(err){showToast(err.message)}}
function beginDeleteConversation(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();state.menuConversationId=item.conversation_id;document.getElementById('deleteConversationCopy').textContent='Permanently delete “'+item.title+'” and all saved messages? This cannot be undone.';document.getElementById('deleteConversationModal').classList.add('open')}
async function confirmDeleteConversation(){const id=state.menuConversationId;if(!id)return;try{await api('/api/conversations/'+encodeURIComponent(id)+'/delete',{method:'POST',body:JSON.stringify({})});closeDeleteConversation();if(state.currentConversationId===id){state.currentConversationId=null;state.currentConversationArchived=false;localStorage.removeItem('workspace.currentConversationId');document.getElementById('conversationName').textContent='New chat';messages.innerHTML='';showEmpty();syncArchivedComposer()}state.menuConversationId=null;showToast('Chat deleted');await loadConversations()}catch(err){showToast(err.message)}}

document.getElementById('archivedChatsBtn').onclick=()=>toggleArchivedView().catch(e=>showToast(e.message));
document.getElementById('conversationRenameAction').onclick=beginRenameConversation;
document.getElementById('conversationPinAction').onclick=()=>toggleConversationPin().catch(e=>showToast(e.message));
document.getElementById('conversationArchiveAction').onclick=()=>toggleConversationArchive().catch(e=>showToast(e.message));
document.getElementById('conversationDeleteAction').onclick=beginDeleteConversation;
document.getElementById('renameConversationForm').addEventListener('submit',submitRenameConversation);
document.getElementById('closeRenameConversation').onclick=closeRenameConversation;
document.getElementById('cancelRenameConversation').onclick=closeRenameConversation;
document.getElementById('closeDeleteConversation').onclick=closeDeleteConversation;
document.getElementById('cancelDeleteConversation').onclick=closeDeleteConversation;
document.getElementById('confirmDeleteConversation').onclick=()=>confirmDeleteConversation().catch(e=>showToast(e.message));
document.addEventListener('click',e=>{if(!e.target.closest('#conversationMenu')&&!e.target.closest('.conversation-more-btn'))closeConversationMenu()});
syncArchivedComposer();
syncArchiveNav();
'''

html = _replace_once(
    html,
    "document.getElementById('sidebarToggle').onclick=toggleSidebar;",
    conversation_js + "\ndocument.getElementById('sidebarToggle').onclick=toggleSidebar;",
    "conversation-js",
)

WORKSPACE_HTML_V4 = html

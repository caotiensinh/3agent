from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v4 import WORKSPACE_HTML_V4

html = WORKSPACE_HTML_V4

project_css = r"""
.projects-heading{display:flex;align-items:center;gap:6px}.projects-heading span{flex:1}.project-add-btn,.project-more-btn{width:27px;height:27px;border:0;background:transparent;border-radius:7px;display:grid;place-items:center;cursor:pointer;color:#92959c}.project-add-btn:hover,.project-more-btn:hover{background:#24262b;color:#fff}.project-add-btn svg,.project-more-btn svg{width:16px;height:16px}.project-row{height:38px;border-radius:9px;display:flex;align-items:center;gap:8px;padding:0 5px 0 10px;cursor:pointer;color:#dfe0e3}.project-row:hover,.project-row.active{background:#18191c}.project-folder{width:18px;height:18px;color:#b9bbc1;flex:0 0 auto}.project-folder svg{width:18px;height:18px}.project-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}.project-count{font-size:10px;color:#73767d}.project-more-btn{opacity:0}.project-row:hover .project-more-btn,.project-row.active .project-more-btn{opacity:1}.project-menu{position:fixed;width:170px;background:#202125;border:1px solid #3a3c43;border-radius:13px;padding:6px;box-shadow:var(--shadow);display:none;z-index:61}.project-menu.open{display:block}.project-menu button{width:100%;height:38px;border:0;background:transparent;border-radius:8px;text-align:left;padding:0 10px;cursor:pointer}.project-menu button:hover{background:#2b2c31}.project-menu button.danger{color:#ffaaaa}.project-menu button.danger:hover{background:#382126}.move-project-list{max-height:320px;overflow:auto;padding:8px}.move-project-row{width:100%;display:flex;align-items:center;gap:9px;border:0;background:transparent;color:#e5e6e9;padding:10px 11px;border-radius:10px;cursor:pointer;text-align:left}.move-project-row:hover,.move-project-row.selected{background:#292b30}.move-project-row svg{width:19px;height:19px}.project-context{font-size:11px;color:#858992;margin-left:7px}.sidebar.collapsed #projectsSection{display:none}
"""
html = _replace_once(html, "</style>", project_css + "</style>", "project-css")

pinned_section = r'''    <section class="history-section" id="pinnedSection">
      <div class="history-heading">Pinned</div>
      <div id="pinnedList"></div>
    </section>'''
projects_section = r'''    <section class="history-section" id="projectsSection">
      <div class="history-heading projects-heading"><span>Projects</span><button class="project-add-btn" id="addProjectBtn" type="button" title="New project" aria-label="New project"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg></button></div>
      <div id="projectsList"></div>
    </section>
''' + pinned_section
html = _replace_once(html, pinned_section, projects_section, "projects-section")

html = _replace_once(
    html,
    '  <button type="button" id="conversationPinAction">Pin</button>\n  <button type="button" id="conversationArchiveAction">Archive</button>',
    '  <button type="button" id="conversationPinAction">Pin</button>\n  <button type="button" id="conversationMoveAction">Move to project</button>\n  <button type="button" id="conversationArchiveAction">Archive</button>',
    "move-conversation-action",
)

project_dialogs = r'''
<div class="project-menu" id="projectMenu">
  <button type="button" id="projectRenameAction">Rename project</button>
  <button type="button" class="danger" id="projectDeleteAction">Delete project</button>
</div>
<div class="library-modal" id="projectEditModal">
  <div class="library-card conversation-dialog">
    <div class="library-head"><h2 id="projectEditTitle">New project</h2><button class="soft-btn" id="closeProjectEdit" type="button">Close</button></div>
    <form class="conversation-dialog-body" id="projectEditForm">
      <input id="projectNameInput" autocomplete="off" maxlength="64" placeholder="Project name" required>
      <div class="dialog-actions"><button class="soft-btn" id="cancelProjectEdit" type="button">Cancel</button><button class="soft-btn primary" type="submit">Save</button></div>
    </form>
  </div>
</div>
<div class="library-modal" id="projectDeleteModal">
  <div class="library-card conversation-dialog">
    <div class="library-head"><h2>Delete project?</h2><button class="soft-btn" id="closeProjectDelete" type="button">Close</button></div>
    <div class="conversation-dialog-body">
      <p class="conversation-dialog-copy" id="projectDeleteCopy">Chats are kept and moved back to the main chat list.</p>
      <div class="dialog-actions"><button class="soft-btn" id="cancelProjectDelete" type="button">Cancel</button><button class="soft-btn danger" id="confirmProjectDelete" type="button">Delete project</button></div>
    </div>
  </div>
</div>
<div class="library-modal" id="moveProjectModal">
  <div class="library-card conversation-dialog">
    <div class="library-head"><h2>Move chat to project</h2><button class="soft-btn" id="closeMoveProject" type="button">Close</button></div>
    <div class="move-project-list" id="moveProjectList"></div>
  </div>
</div>
'''
html = _replace_once(
    html,
    '<div class="library-modal" id="libraryModal">',
    project_dialogs + '<div class="library-modal" id="libraryModal">',
    "project-dialogs",
)

project_js = r'''
state.projects=[];
state.selectedProjectId=null;
state.projectMenuId=null;
state.projectEditId=null;

function projectById(id){return state.projects.find(p=>p.project_id===id)||null}
function folderSvg(){return '<svg viewBox="0 0 24 24"><path d="M3 6h7l2 2h9v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>'}
function closeProjectMenu(){document.getElementById('projectMenu').classList.remove('open');state.projectMenuId=null}
function closeProjectEdit(){document.getElementById('projectEditModal').classList.remove('open');state.projectEditId=null}
function closeProjectDelete(){document.getElementById('projectDeleteModal').classList.remove('open')}
function closeMoveProject(){document.getElementById('moveProjectModal').classList.remove('open')}
function renderProjects(){const wrap=document.getElementById('projectsList');wrap.innerHTML='';for(const p of state.projects){const row=document.createElement('div');row.className='project-row'+(p.project_id===state.selectedProjectId?' active':'');const icon=document.createElement('span');icon.className='project-folder';icon.innerHTML=folderSvg();const name=document.createElement('span');name.className='project-name';name.textContent=p.name;name.title=p.name;const count=document.createElement('span');count.className='project-count';count.textContent=String(p.conversation_count||0);const more=document.createElement('button');more.type='button';more.className='project-more-btn';more.setAttribute('aria-label','Project actions');more.innerHTML='<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>';more.onclick=e=>{e.stopPropagation();openProjectMenu(p.project_id,more)};row.append(icon,name,count,more);row.onclick=()=>selectProject(p.project_id);wrap.appendChild(row)}if(!state.projects.length){const e=document.createElement('div');e.className='history-empty';e.textContent='No projects yet';wrap.appendChild(e)}}
async function loadProjects(){const d=await api('/api/projects');state.projects=d.projects||[];if(state.selectedProjectId&&!state.projects.some(p=>p.project_id===state.selectedProjectId))state.selectedProjectId=null;renderProjects()}
async function selectProject(id){state.selectedProjectId=id;state.searchQuery='';state.historyView='active';const q=document.getElementById('historySearchInput');if(q)q.value='';document.getElementById('historySearchBox').classList.add('hidden');renderProjects();await loadConversations('');if(window.innerWidth<=760)setSidebarCollapsed(true)}
function clearProjectSelection(){if(!state.selectedProjectId)return;state.selectedProjectId=null;renderProjects();loadConversations('').catch(e=>showToast(e.message))}
function openProjectMenu(id,button){const p=projectById(id);if(!p)return;state.projectMenuId=id;const menu=document.getElementById('projectMenu'),r=button.getBoundingClientRect();menu.classList.add('open');menu.style.left=Math.max(8,Math.min(r.right-170,window.innerWidth-178))+'px';menu.style.top=Math.max(8,Math.min(r.bottom+4,window.innerHeight-92))+'px'}
function beginCreateProject(){closeProjectMenu();state.projectEditId=null;document.getElementById('projectEditTitle').textContent='New project';document.getElementById('projectNameInput').value='';document.getElementById('projectEditModal').classList.add('open');setTimeout(()=>document.getElementById('projectNameInput').focus(),30)}
function beginRenameProject(){const p=projectById(state.projectMenuId);if(!p)return;closeProjectMenu();state.projectEditId=p.project_id;document.getElementById('projectEditTitle').textContent='Rename project';document.getElementById('projectNameInput').value=p.name;document.getElementById('projectEditModal').classList.add('open');setTimeout(()=>{const e=document.getElementById('projectNameInput');e.focus();e.select()},30)}
async function submitProjectEdit(e){e.preventDefault();const name=document.getElementById('projectNameInput').value.trim();try{if(state.projectEditId)await api('/api/projects/'+encodeURIComponent(state.projectEditId)+'/rename',{method:'POST',body:JSON.stringify({name})});else await api('/api/projects',{method:'POST',body:JSON.stringify({name})});closeProjectEdit();showToast(state.projectEditId?'Project renamed':'Project created');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}
function beginDeleteProject(){const p=projectById(state.projectMenuId);if(!p)return;closeProjectMenu();state.projectMenuId=p.project_id;document.getElementById('projectDeleteCopy').textContent='Delete “'+p.name+'”? Its chats will be kept and moved back to the main chat list.';document.getElementById('projectDeleteModal').classList.add('open')}
async function confirmProjectDelete(){const id=state.projectMenuId;if(!id)return;try{const d=await api('/api/projects/'+encodeURIComponent(id)+'/delete',{method:'POST',body:JSON.stringify({})});closeProjectDelete();if(state.selectedProjectId===id)state.selectedProjectId=null;state.projectMenuId=null;showToast('Project deleted · '+String(d.detached_conversations||0)+' chats kept');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}
function openMoveProject(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();state.menuConversationId=item.conversation_id;const wrap=document.getElementById('moveProjectList');wrap.innerHTML='';const choices=[{project_id:'',name:'No project'},...state.projects];for(const p of choices){const b=document.createElement('button');b.type='button';b.className='move-project-row'+((item.project_id||'')===(p.project_id||'')?' selected':'');b.innerHTML=folderSvg();const s=document.createElement('span');s.textContent=p.name;b.appendChild(s);b.onclick=()=>moveConversationToProject(item.conversation_id,p.project_id||null);wrap.appendChild(b)}document.getElementById('moveProjectModal').classList.add('open')}
async function moveConversationToProject(conversationId,projectId){try{await api('/api/conversations/'+encodeURIComponent(conversationId)+'/project',{method:'POST',body:JSON.stringify({project_id:projectId})});closeMoveProject();showToast(projectId?'Chat moved to project':'Chat removed from project');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}

function renderHistoryList(){const pinned=document.getElementById('pinnedList'),history=document.getElementById('historyList'),section=document.getElementById('pinnedSection');pinned.innerHTML='';history.innerHTML='';syncArchiveNav();renderProjects();const selected=projectById(state.selectedProjectId);if(state.searchQuery){section.classList.add('hidden');document.getElementById('historyHeading').textContent='Search results';for(const item of state.conversations)history.appendChild(buildConversationRow(item))}else if(state.historyView==='archived'){section.classList.add('hidden');document.getElementById('historyHeading').textContent=selected?selected.name+' · Archived':'Archived';appendTimeGroups(history,state.conversations)}else if(selected){section.classList.add('hidden');document.getElementById('historyHeading').textContent=selected.name;appendTimeGroups(history,state.conversations)}else{const p=state.conversations.filter(x=>x.pinned&&!x.archived),normal=state.conversations.filter(x=>!x.pinned&&!x.archived);section.classList.toggle('hidden',p.length===0);document.getElementById('historyHeading').textContent='Chats';for(const item of p)pinned.appendChild(buildConversationRow(item));appendTimeGroups(history,normal)}if(!state.conversations.length){const e=document.createElement('div');e.className='history-empty';e.textContent=state.searchQuery?'No matching chats':selected?'No chats in this project':(state.historyView==='archived'?'No archived chats':'No saved chats yet');history.appendChild(e)}}
async function loadConversations(query=state.searchQuery){state.searchQuery=String(query||'').trim();const params=new URLSearchParams();if(state.searchQuery){params.set('q',state.searchQuery);params.set('view','all')}else{params.set('view',state.historyView);if(state.selectedProjectId)params.set('project',state.selectedProjectId)}const d=await api('/api/conversations?'+params.toString());state.conversations=d.conversations||[];renderHistoryList()}
async function initializeWorkspace(){await Promise.all([loadCapabilities(),loadSession(),loadProjects()]);await loadConversations('');const remembered=localStorage.getItem('workspace.currentConversationId');if(remembered){try{await openConversation(remembered);return}catch(e){localStorage.removeItem('workspace.currentConversationId')}}newChat()}

document.getElementById('addProjectBtn').onclick=beginCreateProject;
document.getElementById('projectRenameAction').onclick=beginRenameProject;
document.getElementById('projectDeleteAction').onclick=beginDeleteProject;
document.getElementById('projectEditForm').addEventListener('submit',submitProjectEdit);
document.getElementById('closeProjectEdit').onclick=closeProjectEdit;
document.getElementById('cancelProjectEdit').onclick=closeProjectEdit;
document.getElementById('closeProjectDelete').onclick=closeProjectDelete;
document.getElementById('cancelProjectDelete').onclick=closeProjectDelete;
document.getElementById('confirmProjectDelete').onclick=()=>confirmProjectDelete().catch(e=>showToast(e.message));
document.getElementById('conversationMoveAction').onclick=openMoveProject;
document.getElementById('closeMoveProject').onclick=closeMoveProject;
document.addEventListener('click',e=>{if(!e.target.closest('#projectMenu')&&!e.target.closest('.project-more-btn'))closeProjectMenu()});
'''

html = _replace_once(
    html,
    "document.getElementById('sidebarToggle').onclick=toggleSidebar;",
    project_js + "\ndocument.getElementById('sidebarToggle').onclick=toggleSidebar;",
    "project-js",
)

WORKSPACE_HTML_V5 = html

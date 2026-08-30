from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v5 import WORKSPACE_HTML_V5


html = WORKSPACE_HTML_V5

html = _replace_once(
    html,
    "async function selectProject(id){state.selectedProjectId=id;state.searchQuery='';state.historyView='active';const q=document.getElementById('historySearchInput');if(q)q.value='';document.getElementById('historySearchBox').classList.add('hidden');renderProjects();await loadConversations('');if(window.innerWidth<=760)setSidebarCollapsed(true)}",
    "async function selectProject(id){state.selectedProjectId=state.selectedProjectId===id?null:id;state.searchQuery='';state.historyView='active';const q=document.getElementById('historySearchInput');if(q)q.value='';document.getElementById('historySearchBox').classList.add('hidden');renderProjects();await loadConversations('');if(window.innerWidth<=760)setSidebarCollapsed(true)}",
    "toggle-project-selection",
)

html = _replace_once(
    html,
    "async function submitProjectEdit(e){e.preventDefault();const name=document.getElementById('projectNameInput').value.trim();try{if(state.projectEditId)await api('/api/projects/'+encodeURIComponent(state.projectEditId)+'/rename',{method:'POST',body:JSON.stringify({name})});else await api('/api/projects',{method:'POST',body:JSON.stringify({name})});closeProjectEdit();showToast(state.projectEditId?'Project renamed':'Project created');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}",
    "async function submitProjectEdit(e){e.preventDefault();const name=document.getElementById('projectNameInput').value.trim(),editing=!!state.projectEditId,editId=state.projectEditId;try{if(editing)await api('/api/projects/'+encodeURIComponent(editId)+'/rename',{method:'POST',body:JSON.stringify({name})});else await api('/api/projects',{method:'POST',body:JSON.stringify({name})});closeProjectEdit();showToast(editing?'Project renamed':'Project created');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}",
    "project-edit-toast",
)

WORKSPACE_HTML_V6 = html

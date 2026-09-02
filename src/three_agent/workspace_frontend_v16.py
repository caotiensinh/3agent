from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_security_v3 import WORKSPACE_HTML_SECURITY_V3


html = WORKSPACE_HTML_SECURITY_V3


def _insert_after_workflow_description(document: str, markup: str) -> str:
    """Compose Draft Library after the semantic Workflow Studio description field.

    Do not anchor this feature to human-facing copy. Copy changes are expected in an
    enterprise UI and must not make the production gateway unimportable. The stable
    element id is the composition contract; a missing/duplicate id or unexpected
    element shape still fails closed during import/CI.
    """

    token = 'id="workflowDescription"'
    count = document.count(token)
    if count != 1:
        raise RuntimeError(
            "workflow-draft-library-markup: expected exactly one workflowDescription id, "
            f"found {count}"
        )
    token_at = document.index(token)
    open_at = document.rfind("<textarea", 0, token_at + 1)
    close_at = document.find("</textarea>", token_at)
    if open_at < 0 or close_at < 0 or open_at > token_at:
        raise RuntimeError(
            "workflow-draft-library-markup: workflowDescription must remain a textarea"
        )
    insert_at = close_at + len("</textarea>")
    return document[:insert_at] + "\n" + markup + document[insert_at:]


draft_css = r"""
.workflow-library-toolbar{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin:-4px 0 12px;padding:9px;border:1px solid #33363c;border-radius:10px;background:#17181b}.workflow-library-toolbar input{min-width:220px;flex:1;background:#111216;color:var(--text);border:1px solid #3b3d43;border-radius:8px;padding:8px 9px}.workflow-library-current{font-size:10px;color:var(--muted);word-break:break-all}.workflow-library-drawer{margin:0 0 12px;border:1px solid #383b42;border-radius:12px;background:#121317;padding:11px}.workflow-library-filters{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-bottom:9px}.workflow-library-filters input{min-width:220px;flex:1;background:#0e0f12;color:var(--text);border:1px solid #35383f;border-radius:8px;padding:8px 9px}.workflow-library-filters select{background:#1b1d21;color:var(--text);border:1px solid #35383f;border-radius:8px;padding:8px 9px}.workflow-library-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}.workflow-library-item{border:1px solid #30333a;background:#17191d;border-radius:10px;padding:10px;cursor:pointer;text-align:left;color:var(--text)}.workflow-library-item:hover,.workflow-library-item:focus-visible{border-color:#555a66;outline:0}.workflow-library-item b{display:block;font-size:12px;margin-bottom:4px}.workflow-library-item span{display:block;font-size:10px;color:var(--muted);line-height:1.45}.workflow-library-item.archived{opacity:.68}.workflow-library-version-list{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.workflow-library-version{border:1px solid #353941;border-radius:999px;padding:4px 7px;font-size:9px;color:#b8bdc7}.workflow-library-authority{font-size:10px;color:#82c99a;margin-left:auto}@media(max-width:700px){.workflow-library-toolbar input,.workflow-library-filters input{min-width:100%;width:100%}.workflow-library-authority{width:100%;margin-left:0}}
"""
html = _replace_once(html, "</style>", draft_css + "</style>", "workflow-draft-library-css")

draft_markup = r"""
    <div class="workflow-library-toolbar">
      <button type="button" class="soft-btn" id="workflowLibraryBtn">My Workflows</button>
      <input id="workflowDraftTitle" maxlength="120" placeholder="Workflow name">
      <button type="button" class="soft-btn" id="workflowDraftCreateBtn">Save new</button>
      <button type="button" class="soft-btn" id="workflowDraftSaveBtn" disabled>Save revision</button>
      <button type="button" class="soft-btn" id="workflowDraftDuplicateBtn" disabled>Duplicate</button>
      <button type="button" class="soft-btn" id="workflowDraftArchiveBtn" disabled>Archive</button>
      <span class="workflow-library-authority">Draft = design only · execution authority unchanged</span>
      <div class="workflow-library-current" id="workflowDraftCurrent" style="width:100%">Unsaved workflow</div>
    </div>
    <div class="workflow-library-drawer workflow-hidden" id="workflowLibraryDrawer">
      <div class="workflow-library-filters">
        <input id="workflowLibrarySearch" maxlength="200" placeholder="Search workflows">
        <select id="workflowLibraryView"><option value="active">Active</option><option value="archived">Archived</option><option value="all">All</option></select>
        <button type="button" class="soft-btn" id="workflowLibraryRefresh">Refresh</button>
      </div>
      <div class="workflow-library-list" id="workflowLibraryList"><div class="library-empty">Open My Workflows to load saved designs.</div></div>
      <div class="workflow-library-version-list" id="workflowDraftVersions"></div>
    </div>
"""
html = _insert_after_workflow_description(html, draft_markup)

draft_js = r"""
(function(){
const drawer=document.getElementById('workflowLibraryDrawer'),list=document.getElementById('workflowLibraryList'),versions=document.getElementById('workflowDraftVersions'),titleInput=document.getElementById('workflowDraftTitle'),desc=document.getElementById('workflowDescription'),json=document.getElementById('workflowJson'),mermaid=document.getElementById('workflowMermaid'),diagram=document.getElementById('workflowDiagram'),steps=document.getElementById('workflowSteps'),warnings=document.getElementById('workflowWarnings'),currentMeta=document.getElementById('workflowDraftCurrent'),saveBtn=document.getElementById('workflowDraftSaveBtn'),duplicateBtn=document.getElementById('workflowDraftDuplicateBtn'),archiveBtn=document.getElementById('workflowDraftArchiveBtn');
let current=null;
function el(tag,text,cls){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n}
function contractFromCanvas(){const raw=(json.textContent||'').trim();if(!raw)throw new Error('Compile or open a workflow first');const c=JSON.parse(raw);if(!c||typeof c!=='object')throw new Error('Workflow contract unavailable');return c}
function currentTitle(contract){return titleInput.value.trim()||String(contract.title||'Untitled workflow').slice(0,120)}
function setCurrent(d){current=d||null;if(!d){currentMeta.textContent='Unsaved workflow';saveBtn.disabled=true;duplicateBtn.disabled=true;archiveBtn.disabled=true;archiveBtn.textContent='Archive';return}titleInput.value=d.title||'';currentMeta.textContent=d.draft_id+' · revision '+d.revision+' · '+d.status+' · '+d.content_sha256.slice(0,12)+'…';saveBtn.disabled=d.status!=='active';duplicateBtn.disabled=false;archiveBtn.disabled=false;archiveBtn.textContent=d.status==='archived'?'Restore':'Archive'}
function renderDraft(d){setCurrent(d);desc.value=d.description||'';const c=d.contract||{};document.getElementById('workflowRisk').textContent='Risk: '+(c.risk_level||'—');document.getElementById('workflowDataClass').textContent='Data: '+(c.data_class||'—');document.getElementById('workflowStatus').textContent='Design only · no execution';diagram.innerHTML=d.diagram?.svg||'<div class="library-empty">Diagram unavailable.</div>';steps.innerHTML='';for(const n of c.nodes||[]){const row=el('div','', 'workflow-step');row.append(el('strong',n.label||n.id),el('span',(n.kind||'')+' · '+(n.action||'')+(n.approval_required?' · approval required':'')));steps.append(row)}if(!(c.nodes||[]).length)steps.append(el('div','No steps.','library-empty'));warnings.innerHTML='';for(const w of c.warnings||[])warnings.append(el('div',w,'workflow-warning'));if(!(c.warnings||[]).length)warnings.append(el('div','No warnings.','library-empty'));mermaid.textContent=d.diagram?.mermaid||'';json.textContent=JSON.stringify(c,null,2)}
async function loadVersions(){versions.innerHTML='';if(!current)return;try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/versions');for(const v of d.versions||[])versions.append(el('span','v'+v.revision+' · '+v.origin+' · '+v.content_sha256.slice(0,8),'workflow-library-version'))}catch(e){versions.append(el('span','Version history unavailable: '+e.message,'workflow-warning'))}}
async function openDraft(id){try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(id));renderDraft(d.draft);await loadVersions();showToast('Workflow draft opened — execution remains unauthorized')}catch(e){showToast('Cannot open workflow: '+e.message)}}
function renderList(rows){list.innerHTML='';for(const d of rows||[]){const b=el('button','', 'workflow-library-item'+(d.status==='archived'?' archived':''));b.type='button';b.append(el('b',d.title),el('span','rev '+d.revision+' · '+d.status+' · '+d.node_count+' nodes'),el('span',(d.risk_level||'—')+' risk · '+(d.data_class||'—')+' data'),el('span',d.updated_at||''));b.onclick=()=>openDraft(d.draft_id);list.append(b)}if(!(rows||[]).length)list.append(el('div','No workflows found.','library-empty'))}
async function loadLibrary(){const q=document.getElementById('workflowLibrarySearch').value.trim(),view=document.getElementById('workflowLibraryView').value;try{const d=await api('/api/workflows/drafts?view='+encodeURIComponent(view)+'&q='+encodeURIComponent(q));renderList(d.drafts)}catch(e){list.innerHTML='';list.append(el('div','Load failed: '+e.message,'workflow-warning'))}}
async function saveNew(){try{const c=contractFromCanvas();const d=await api('/api/workflows/drafts',{method:'POST',body:JSON.stringify({title:currentTitle(c),description:desc.value,contract:c,origin:'workspace_ai'})});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast('Workflow saved as revision 1')}catch(e){showToast('Save blocked: '+e.message)}}
async function saveRevision(){if(!current){showToast('Save a new workflow first');return}try{const c=contractFromCanvas();const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/save',{method:'POST',body:JSON.stringify({expected_revision:current.revision,expected_content_sha256:current.content_sha256,title:currentTitle(c),description:desc.value,contract:c,origin:'human'})});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast('Workflow revision saved')}catch(e){showToast('Revision save blocked: '+e.message+' — reload if this draft changed elsewhere')}}
async function duplicateDraft(){if(!current)return;try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/duplicate',{method:'POST',body:'{}'});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast('Independent workflow copy created')}catch(e){showToast('Duplicate blocked: '+e.message)}}
async function toggleArchive(){if(!current)return;const action=current.status==='archived'?'restore':'archive';try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/'+action,{method:'POST',body:'{}'});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast(action==='archive'?'Workflow archived':'Workflow restored')}catch(e){showToast('Lifecycle change blocked: '+e.message)}}
document.getElementById('workflowLibraryBtn').onclick=()=>{drawer.classList.toggle('workflow-hidden');if(!drawer.classList.contains('workflow-hidden'))loadLibrary()};document.getElementById('workflowLibraryRefresh').onclick=loadLibrary;document.getElementById('workflowLibrarySearch').addEventListener('keydown',e=>{if(e.key==='Enter')loadLibrary()});document.getElementById('workflowLibraryView').onchange=loadLibrary;document.getElementById('workflowDraftCreateBtn').onclick=saveNew;saveBtn.onclick=saveRevision;duplicateBtn.onclick=duplicateDraft;archiveBtn.onclick=toggleArchive;
})();
"""
html = _replace_once(html, "</body>", f"<script>{draft_js}</script></body>", "workflow-draft-library-js")

WORKSPACE_HTML_V16 = html

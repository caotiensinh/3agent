from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v17 import WORKSPACE_HTML_V17


html = WORKSPACE_HTML_V17

legacy_load_admin = "async function loadAdmin(){const grid=document.getElementById('securityAdminGrid');grid.innerHTML='';try{const d=await api('/api/security/admin');for(const key of ['config_state','database_available','schema_version_db','enabled','allow_real_network','asset_count','secret_boundary_configured','read_only_ui','mutations_exposed','autonomous_remediation','autonomous_pcap','passive_sensors_optional'])adminKV(grid,key,d[key]);adminKV(grid,'policy',d.policy||{})}catch(e){adminKV(grid,'Administration',e.message)}}"

enhanced_load_admin = r"""function securityReadonlyAction(grid){const box=document.createElement('div');box.className='security-kv';const title=document.createElement('b');title.textContent='Read-only monitoring execution';const note=document.createElement('span');note.textContent='Admin-confirmed collection only. Uses the server-configured asset inventory and policy; the browser cannot submit targets, paths, credentials, collectors, shell commands, packet capture, or remediation.';const button=document.createElement('button');button.type='button';button.className='soft-btn';button.id='securityRunReadonly';button.textContent='Run read-only monitoring';button.onclick=runSecurityReadonlyMonitoring;box.append(title,note,button);grid.appendChild(box)}
async function runSecurityReadonlyMonitoring(){if(!window.confirm('Run the approved read-only monitoring plan now? This may perform network reads against assets already approved in the server configuration.'))return;const button=document.getElementById('securityRunReadonly');if(button)button.disabled=true;try{const response=await fetch('/api/security/monitoring/run-readonly',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Workspace-Action':'security-readonly-monitoring'},body:JSON.stringify({confirmation:'RUN_READONLY_MONITORING'})});let payload={};try{payload=await response.json()}catch(e){}if(!response.ok)throw new Error(payload.code||'SECURITY_MONITORING_RUN_FAILED');showToast('Read-only monitoring completed');await refreshSecurityBadge();await loadAdmin()}catch(e){showToast('Security Analyst: '+e.message)}finally{const current=document.getElementById('securityRunReadonly');if(current)current.disabled=false}}
async function loadAdmin(){const grid=document.getElementById('securityAdminGrid');grid.innerHTML='';try{const d=await api('/api/security/admin');for(const key of ['config_state','database_available','schema_version_db','enabled','allow_real_network','asset_count','secret_boundary_configured','read_only_ui','mutations_exposed','autonomous_remediation','autonomous_pcap','passive_sensors_optional'])adminKV(grid,key,d[key]);adminKV(grid,'policy',d.policy||{});securityReadonlyAction(grid)}catch(e){adminKV(grid,'Administration',e.message)}}"""

html = _replace_once(
    html,
    legacy_load_admin,
    enhanced_load_admin,
    "security-readonly-monitoring-action",
)

WORKSPACE_HTML_SECURITY_ACTIONS_V1 = html

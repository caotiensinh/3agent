from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v16 import WORKSPACE_HTML_V16


html = WORKSPACE_HTML_V16

closure_css = r'''
.security-confirmation-box{margin-top:10px;border:1px solid #5a4930;background:#211a10;border-radius:10px;padding:10px}.security-confirmation-box label{display:block;font-size:10px;color:#e3c895;margin-bottom:6px}.security-confirmation-box input{width:100%;box-sizing:border-box;border:1px solid #62533a;background:#0e1013;color:#f1e6cf;border-radius:8px;padding:8px 9px;font:10px ui-monospace,SFMono-Regular,Consolas,monospace}.security-confirmation-box small{display:block;color:#b9a27c;font-size:9px;line-height:1.45;margin-top:6px}.security-audit-list{display:flex;flex-direction:column;gap:6px;max-height:260px;overflow:auto}.security-audit-row{border:1px solid #30343b;border-radius:8px;background:#0e1013;padding:8px}.security-audit-row b{display:block;color:#c8ccd4;font-size:10px}.security-audit-row span{display:block;color:#818792;font-size:9px;line-height:1.45;margin-top:3px;word-break:break-word}.security-runtime-value{font:10px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
'''
html = _replace_once(html, "</style>", closure_css + "</style>", "security-e2e-closure-css")

confirmation_markup = r'''
              <div class="security-confirmation-box">
                <label for="secCfgStrongConfirmation">Strong confirmation for real-network authority changes</label>
                <input id="secCfgStrongConfirmation" autocomplete="off" spellcheck="false" placeholder="ENABLE_APPROVED_REAL_NETWORK_MONITORING">
                <small>Required by the backend when enabling approved real-network reads, enabling active liveness, enabling monitoring while real-network reads are armed, or changing approved inventory/policy while real-network monitoring is enabled. Saving itself never runs a collector or network action.</small>
              </div>
'''
html = _replace_once(
    html,
    '              <div class="security-config-meta" id="secCfgMeta"></div>',
    confirmation_markup + '              <div class="security-config-meta" id="secCfgMeta"></div>',
    "security-strong-confirmation",
)

audit_markup = r'''
            <div class="security-config-panel" style="margin-top:12px">
              <div class="security-asset-head"><div><h3 style="margin:0">Configuration audit</h3><div class="security-config-help" style="margin:3px 0 0">Metadata only. Management hosts, credential references and raw secret material are never written to this audit view.</div></div><button class="soft-btn" id="secCfgAuditReload" type="button">Reload</button></div>
              <div class="security-kv"><b>Running source SHA</b><span class="security-runtime-value" id="secCfgRuntimeSha">—</span></div>
              <div class="security-kv" style="margin-top:7px"><b>Gateway</b><span id="secCfgRuntimeGateway">—</span></div>
              <div class="security-audit-list" id="secCfgAuditRows" style="margin-top:8px"><div class="security-empty">No audit data loaded.</div></div>
            </div>
'''
html = _replace_once(
    html,
    '            <div class="security-config-panel" style="margin-top:12px">\n              <h3>Recommended telemetry strategy</h3>',
    audit_markup + '            <div class="security-config-panel" style="margin-top:12px">\n              <h3>Recommended telemetry strategy</h3>',
    "security-config-audit-panel",
)

closure_js = r'''
(function(){
const CONFIRMATION='ENABLE_APPROVED_REAL_NETWORK_MONITORING';
const originalFetch=window.fetch.bind(window);
function requestPath(input){try{return new URL(typeof input==='string'?input:input.url,window.location.href).pathname}catch(e){return ''}}
window.fetch=async function(input,init){
  let options=init?{...init}:{};
  if(requestPath(input)==='/api/security/config/save' && String(options.method||'GET').toUpperCase()==='POST' && options.body){
    try{
      const payload=JSON.parse(options.body);
      const field=document.getElementById('secCfgStrongConfirmation');
      payload.confirmation=field?field.value.trim():'';
      options.body=JSON.stringify(payload);
    }catch(e){}
  }
  const response=await originalFetch(input,options);
  if(requestPath(input)==='/api/security/config/save' && response.ok){
    const field=document.getElementById('secCfgStrongConfirmation');
    if(field)field.value='';
    window.setTimeout(loadClosureSecurityMeta,50);
  }
  return response;
};
function auditText(item){
  const changed=Array.isArray(item.changed_sections)?item.changed_sections.join(', '):'—';
  const reasons=Array.isArray(item.confirmation_reasons)&&item.confirmation_reasons.length?item.confirmation_reasons.join(', '):'none';
  return 'changed='+changed+' · assets='+String(item.asset_count??'—')+' · real_network='+String(!!item.allow_real_network)+' · confirmation='+reasons;
}
function renderAudit(items){
  const root=document.getElementById('secCfgAuditRows');if(!root)return;root.innerHTML='';
  if(!items.length){const empty=document.createElement('div');empty.className='security-empty';empty.textContent='No configuration audit records yet.';root.appendChild(empty);return}
  for(const item of items){const row=document.createElement('div');row.className='security-audit-row';const b=document.createElement('b');b.textContent=item.recorded_at||'audit';const s=document.createElement('span');s.textContent=auditText(item);row.append(b,s);root.appendChild(row)}
}
async function loadClosureSecurityMeta(){
  try{const r=await originalFetch('/api/security/runtime',{credentials:'same-origin'});const d=await r.json();if(r.ok){const sha=document.getElementById('secCfgRuntimeSha'),gw=document.getElementById('secCfgRuntimeGateway');if(sha)sha.textContent=d.source_sha||'unknown';if(gw)gw.textContent=d.gateway||'unknown'}}catch(e){}
  try{const r=await originalFetch('/api/security/config/audit?limit=20',{credentials:'same-origin'});const d=await r.json();if(r.ok)renderAudit(Array.isArray(d.items)?d.items:[])}catch(e){}
}
const reload=document.getElementById('secCfgAuditReload');if(reload)reload.onclick=()=>loadClosureSecurityMeta();
const tab=document.getElementById('securityConfigTab');if(tab)tab.addEventListener('click',()=>window.setTimeout(loadClosureSecurityMeta,0));
const real=document.getElementById('secCfgRealNetwork');if(real)real.addEventListener('change',()=>{const field=document.getElementById('secCfgStrongConfirmation');if(real.checked&&field&&!field.value)field.placeholder=CONFIRMATION});
})();
'''
html = _replace_once(
    html,
    "</body>",
    f"<script>{closure_js}</script></body>",
    "security-e2e-closure-js",
)

WORKSPACE_HTML_V17 = html

from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v14 import WORKSPACE_HTML_V14


html = WORKSPACE_HTML_V14

config_css = r'''
.security-config-layout{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(300px,.75fr);gap:12px}.security-config-panel{border:1px solid #30333a;background:#121418;border-radius:12px;padding:13px}.security-config-panel h3{font-size:13px;margin:0 0 10px}.security-config-help{color:#858a94;font-size:10px;line-height:1.45;margin:-4px 0 10px}.security-config-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-config-field{display:flex;flex-direction:column;gap:5px}.security-config-field.wide{grid-column:1/-1}.security-config-field label,.security-switch span{font-size:10px;color:#9398a2}.security-config-field input,.security-config-field select{width:100%;box-sizing:border-box;border:1px solid #363a42;background:#0e1013;color:#e7e9ed;border-radius:8px;padding:8px 9px;font-size:11px}.security-switch{display:flex;align-items:center;justify-content:space-between;gap:9px;border:1px solid #30343b;border-radius:9px;padding:8px 9px;background:#101216}.security-switch input{width:17px;height:17px}.security-policy-lock{border:1px solid #2e473d;background:#101c17;border-radius:10px;padding:10px;color:#b9d7c8;font-size:10px;line-height:1.55}.security-policy-warning{border-color:#5a4930;background:#211a10;color:#e3c895}.security-config-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.security-config-status{margin-top:10px;border:1px solid #30343b;border-radius:9px;padding:9px;font:10px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-word;min-height:38px;background:#0d0f12}.security-assets{display:flex;flex-direction:column;gap:8px}.security-asset-editor{border:1px solid #30343b;border-radius:10px;padding:10px;background:#0f1115}.security-asset-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}.security-asset-head b{font-size:11px}.security-cap-list{display:flex;gap:7px;flex-wrap:wrap;margin-top:3px}.security-cap-list label{display:flex;align-items:center;gap:4px;color:#b2b6bf;font-size:10px}.security-danger-note{font-size:10px;color:#e3c895;line-height:1.45;margin-top:7px}.security-config-meta{display:grid;gap:7px;margin-top:10px}.security-config-meta .security-kv{padding:8px}.security-config-footer-note{margin-top:11px;color:#777c86;font-size:10px;line-height:1.5}@media(max-width:980px){.security-config-layout{grid-template-columns:1fr}}@media(max-width:640px){.security-config-grid{grid-template-columns:1fr}.security-config-field.wide{grid-column:auto}}
'''
html = _replace_once(html, "</style>", config_css + "</style>", "security-config-css")

html = _replace_once(
    html,
    '        <button class="security-tab" data-security-tab="admin" id="securityAdminTab" type="button">Administration</button>',
    '        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>\n        <button class="security-tab" data-security-tab="admin" id="securityAdminTab" type="button">Administration</button>',
    "security-config-tab",
)

config_markup = r'''
      <div class="security-view" data-security-view="configuration" id="securityConfigView">
        <div class="security-config-layout">
          <div>
            <div class="security-config-panel">
              <h3>Monitoring &amp; safety policy</h3>
              <div class="security-config-help">Configuration is admin-only. Saving never starts collectors, scans, packet capture, remediation, or shell commands.</div>
              <div class="security-config-grid">
                <div class="security-switch"><span>Enable monitoring</span><input id="secCfgEnabled" type="checkbox"></div>
                <div class="security-switch"><span>Allow approved real-network reads</span><input id="secCfgRealNetwork" type="checkbox"></div>
                <div class="security-config-field"><label>Profile ID</label><input id="secCfgProfile" value="default" maxlength="128"></div>
                <div class="security-config-field"><label>Max workers (1–4)</label><input id="secCfgWorkers" type="number" min="1" max="4" value="4"></div>
                <div class="security-config-field"><label>Timeout seconds (0.1–5)</label><input id="secCfgTimeout" type="number" min="0.1" max="5" step="0.1" value="3"></div>
                <div class="security-config-field"><label>Max retries (0–1)</label><input id="secCfgRetries" type="number" min="0" max="1" value="1"></div>
                <div class="security-switch wide"><span>Allow active liveness (ICMP/TCP only, never throughput)</span><input id="secCfgActiveLiveness" type="checkbox"></div>
              </div>
              <div class="security-policy-lock" style="margin-top:9px">Locked safety boundary: approved_inventory_only · read_only · non_disruptive_v1 · counter_only bandwidth · passive_only packet analysis.</div>
              <div class="security-config-field wide" style="margin-top:9px"><label>Allowed capabilities</label><div class="security-cap-list" id="secCfgCaps"><label><input type="checkbox" value="snmpv3_read" checked> SNMPv3 read</label><label><input type="checkbox" value="local_net_read" checked> Local telemetry read</label><label><input type="checkbox" value="icmp_echo"> ICMP liveness</label><label><input type="checkbox" value="tcp_connect"> TCP liveness</label></div></div>
            </div>

            <div class="security-config-panel" style="margin-top:12px">
              <h3>Local data &amp; secret boundary</h3>
              <div class="security-config-help">Only opaque secret references are stored in monitoring configuration. Passwords, SNMP communities, tokens, auth keys and private keys are rejected by the backend contract.</div>
              <div class="security-config-grid">
                <div class="security-config-field wide"><label>Monitoring database path</label><input id="secCfgDatabase" autocomplete="off"></div>
                <div class="security-config-field wide"><label>Local secret directory</label><input id="secCfgSecretDir" autocomplete="off"></div>
              </div>
            </div>

            <div class="security-config-panel" style="margin-top:12px">
              <div class="security-asset-head"><div><h3 style="margin:0">Approved asset inventory</h3><div class="security-config-help" style="margin:3px 0 0">Collectors can target only assets and capabilities explicitly listed here.</div></div><button class="soft-btn" id="secCfgAddAsset" type="button">Add asset</button></div>
              <div class="security-assets" id="secCfgAssets"></div>
            </div>
          </div>

          <div>
            <div class="security-config-panel">
              <h3>Configuration gate</h3>
              <div class="security-policy-lock">Fail-closed defaults: monitoring off, real network off, passive packet analysis, no autonomous remediation, no web PCAP execution.</div>
              <div class="security-config-actions">
                <button class="soft-btn" id="secCfgReload" type="button">Reload</button>
                <button class="soft-btn" id="secCfgValidate" type="button">Validate</button>
                <button class="soft-btn" id="secCfgReadiness" type="button">Readiness check</button>
                <button class="soft-btn" id="secCfgSave" type="button">Save configuration</button>
              </div>
              <div class="security-config-status" id="secCfgStatus">Open Configuration to load the current policy.</div>
              <div class="security-config-meta" id="secCfgMeta"></div>
              <div class="security-config-footer-note">Readiness check verifies configuration, local paths and opaque credential references only. It does not probe the network or read secret values.</div>
            </div>
            <div class="security-config-panel" style="margin-top:12px">
              <h3>Recommended telemetry strategy</h3>
              <div class="security-config-help">Prefer passive/read-only evidence first: device counters and approved local telemetry. Structured IDS/NSM events can feed the existing event pipeline without granting the AI direct network authority.</div>
              <div class="security-kv"><b>Default collection</b><span>SNMPv3 read-only + local telemetry</span></div>
              <div class="security-kv" style="margin-top:7px"><b>Packet analysis</b><span>Passive only; incident PCAP requires separate admin approval and dedicated runner</span></div>
              <div class="security-kv" style="margin-top:7px"><b>Actions</b><span>Advisory only; no automatic firewall/block/remediation authority</span></div>
            </div>
          </div>
        </div>
      </div>

'''
html = _replace_once(
    html,
    '      <div class="security-view" data-security-view="admin">',
    config_markup + '      <div class="security-view" data-security-view="admin">',
    "security-config-view",
)

config_js = r'''
(function(){
const tab=document.getElementById('securityConfigTab'),view=document.getElementById('securityConfigView'),status=document.getElementById('secCfgStatus'),assets=document.getElementById('secCfgAssets'),meta=document.getElementById('secCfgMeta');
let loadedEnvelope=null;
function cfgText(id){return document.getElementById(id).value.trim()}
function cfgBool(id){return !!document.getElementById(id).checked}
function cfgNumber(id){return Number(document.getElementById(id).value)}
function setStatus(message,ok=null){status.textContent=message;status.style.borderColor=ok===true?'#315a46':ok===false?'#694040':'#30343b'}
function metaKV(key,value){const box=document.createElement('div');box.className='security-kv';const b=document.createElement('b');b.textContent=key;const s=document.createElement('span');s.textContent=value===undefined||value===null?'—':String(value);box.append(b,s);meta.appendChild(box)}
function selectedCaps(){return Array.from(document.querySelectorAll('#secCfgCaps input:checked')).map(x=>x.value)}
function setSelectedCaps(values){const set=new Set(values||[]);for(const x of document.querySelectorAll('#secCfgCaps input'))x.checked=set.has(x.value)}
function assetEditor(item={}){const box=document.createElement('div');box.className='security-asset-editor';box.innerHTML='<div class="security-asset-head"><b>Approved asset</b><button class="soft-btn secAssetRemove" type="button">Remove</button></div><div class="security-config-grid"><div class="security-config-field"><label>Asset ID</label><input class="secAssetId" maxlength="128"></div><div class="security-config-field"><label>Role</label><input class="secAssetRole" maxlength="64" placeholder="router / switch / server"></div><div class="security-config-field"><label>Management host</label><input class="secAssetHost" maxlength="253" placeholder="192.168.11.1"></div><div class="security-config-field"><label>Data class</label><select class="secAssetClass"><option>public</option><option>internal</option><option selected>confidential</option><option>restricted</option><option>secret</option></select></div><div class="security-switch"><span>Enabled</span><input class="secAssetEnabled" type="checkbox" checked></div><div class="security-config-field"><label>Allowed TCP ports</label><input class="secAssetPorts" placeholder="443, 22"></div><div class="security-config-field wide"><label>Collector capabilities</label><div class="security-cap-list secAssetCaps"><label><input type="checkbox" value="snmpv3_read"> SNMPv3 read</label><label><input type="checkbox" value="local_net_read"> Local read</label><label><input type="checkbox" value="icmp_echo"> ICMP</label><label><input type="checkbox" value="tcp_connect"> TCP connect</label><label><input type="checkbox" value="fixed_readonly_adapter"> Fixed read-only adapter</label></div></div><div class="security-config-field wide"><label>Credential reference (opaque; SNMPv3 only)</label><input class="secAssetCredential" placeholder="secret-ref:router-snmpv3" autocomplete="off"></div></div>';
box.querySelector('.secAssetId').value=item.asset_id||'';box.querySelector('.secAssetRole').value=item.role||'';box.querySelector('.secAssetHost').value=item.management_host||'';box.querySelector('.secAssetClass').value=item.data_class||'confidential';box.querySelector('.secAssetEnabled').checked=item.enabled!==false;box.querySelector('.secAssetPorts').value=(item.allowed_tcp_ports||[]).join(', ');box.querySelector('.secAssetCredential').value=item.credential_ref||'';const caps=new Set(item.collector_capabilities||[]);for(const x of box.querySelectorAll('.secAssetCaps input'))x.checked=caps.has(x.value);box.querySelector('.secAssetRemove').onclick=()=>box.remove();return box}
function readAssets(){return Array.from(assets.querySelectorAll('.security-asset-editor')).map(box=>({asset_id:box.querySelector('.secAssetId').value.trim(),role:box.querySelector('.secAssetRole').value.trim(),management_host:box.querySelector('.secAssetHost').value.trim(),collector_capabilities:Array.from(box.querySelectorAll('.secAssetCaps input:checked')).map(x=>x.value),allowed_tcp_ports:box.querySelector('.secAssetPorts').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number),data_class:box.querySelector('.secAssetClass').value,enabled:box.querySelector('.secAssetEnabled').checked,credential_ref:box.querySelector('.secAssetCredential').value.trim()||null}))}
function currentPayload(){return {enabled:cfgBool('secCfgEnabled'),allow_real_network:cfgBool('secCfgRealNetwork'),database_path:cfgText('secCfgDatabase'),secret_directory:cfgText('secCfgSecretDir')||null,policy:{profile_id:cfgText('secCfgProfile'),network_scope:'approved_inventory_only',read_only:true,production_safety_profile:'non_disruptive_v1',allow_active_liveness:cfgBool('secCfgActiveLiveness'),bandwidth_measurement_mode:'counter_only',packet_analysis_mode:'passive_only',max_workers:cfgNumber('secCfgWorkers'),timeout_seconds:cfgNumber('secCfgTimeout'),max_retries:cfgNumber('secCfgRetries'),max_catch_up_runs:1,allowed_capabilities:selectedCaps()},assets:readAssets()}}
function fill(payload){document.getElementById('secCfgEnabled').checked=!!payload.enabled;document.getElementById('secCfgRealNetwork').checked=!!payload.allow_real_network;document.getElementById('secCfgDatabase').value=payload.database_path||'';document.getElementById('secCfgSecretDir').value=payload.secret_directory||'';const p=payload.policy||{};document.getElementById('secCfgProfile').value=p.profile_id||'default';document.getElementById('secCfgWorkers').value=p.max_workers??4;document.getElementById('secCfgTimeout').value=p.timeout_seconds??3;document.getElementById('secCfgRetries').value=p.max_retries??1;document.getElementById('secCfgActiveLiveness').checked=!!p.allow_active_liveness;setSelectedCaps(p.allowed_capabilities||['snmpv3_read','local_net_read']);assets.innerHTML='';for(const item of payload.assets||[])assets.appendChild(assetEditor(item))}
function renderEnvelope(d){loadedEnvelope=d;fill(d.config||{});meta.innerHTML='';metaKV('State',d.state);metaKV('Config path',d.config_path);metaKV('Path source',d.path_source);metaKV('Policy fingerprint',d.summary?.policy_fingerprint);setStatus(d.state==='configured'?'Configuration loaded.':'Safe defaults loaded but not saved.',true)}
async function loadConfig(){try{setStatus('Loading configuration…');renderEnvelope(await api('/api/security/config'))}catch(e){setStatus('Load failed: '+e.message,false)}}
async function postConfig(path,payload){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(payload)});let d={};try{d=await r.json()}catch(e){}if(!r.ok)throw new Error(d.error||d.code||('HTTP '+r.status));return d}
async function validateConfig(){try{setStatus('Validating…');const d=await postConfig('/api/security/config/validate',{config:currentPayload()});setStatus('VALID\nPolicy: '+d.summary.policy_fingerprint+'\nAssets: '+d.summary.asset_count+'\nReady: '+d.readiness.ready,true)}catch(e){setStatus('INVALID\n'+e.message,false)}}
async function readiness(){try{setStatus('Checking local readiness…');const d=await postConfig('/api/security/config/readiness',{});const lines=['Ready: '+d.ready,'Network test executed: '+d.network_test_executed,'Secret values read: '+d.secret_values_read];for(const x of d.issues||[])lines.push('BLOCKER '+x.code+': '+x.message);for(const x of d.warnings||[])lines.push('WARNING '+x.code+': '+x.message);setStatus(lines.join('\n'),d.ready)}catch(e){setStatus('Readiness failed: '+e.message,false)}}
async function saveConfig(){const payload=currentPayload();if(payload.policy.allow_active_liveness&&!confirm('Active liveness generates ICMP/TCP probe traffic to explicitly approved inventory only. Continue saving?'))return;if(payload.allow_real_network&&!confirm('Allow read-only network collection for explicitly approved assets? Saving does not start collection.'))return;try{setStatus('Validating and saving…');const d=await postConfig('/api/security/config/save',{config:payload});setStatus('SAVED\nPolicy: '+d.summary.policy_fingerprint+'\nReady: '+d.readiness.ready,true);await loadConfig();if(typeof refreshSecurityBadge==='function')refreshSecurityBadge()}catch(e){setStatus('SAVE BLOCKED\n'+e.message,false)}}
function openConfig(){if(state.session?.role!=='admin'){showToast('Administrator role required');return}for(const b of document.querySelectorAll('[data-security-tab]'))b.classList.toggle('active',b===tab);for(const v of document.querySelectorAll('[data-security-view]'))v.classList.toggle('active',v===view);loadConfig()}
function updateAccess(){tab.classList.toggle('hidden',state.session?.role!=='admin')}
tab.onclick=openConfig;document.getElementById('secCfgAddAsset').onclick=()=>assets.appendChild(assetEditor());document.getElementById('secCfgReload').onclick=loadConfig;document.getElementById('secCfgValidate').onclick=validateConfig;document.getElementById('secCfgReadiness').onclick=readiness;document.getElementById('secCfgSave').onclick=saveConfig;document.getElementById('securityAnalystBtn').addEventListener('click',updateAccess);document.getElementById('loginBtn').addEventListener('click',()=>setTimeout(updateAccess,500));updateAccess();
})();
'''
html = _replace_once(html, "</body>", f"<script>{config_js}</script></body>", "security-config-js")

WORKSPACE_HTML_V15 = html

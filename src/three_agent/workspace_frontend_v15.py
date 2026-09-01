from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v14 import WORKSPACE_HTML_V14


html = WORKSPACE_HTML_V14

config_css = r"""
.security-config-launch{margin-top:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}.security-config-note{font-size:10px;color:#8f939c}.security-config-center{display:none;margin-top:12px;border:1px solid #30333a;border-radius:12px;background:#101216;padding:14px}.security-config-center.open{display:block}.security-config-head{display:flex;align-items:flex-start;gap:10px;margin-bottom:12px}.security-config-head-copy{flex:1}.security-config-head h3{margin:0;font-size:16px}.security-config-head p{margin:4px 0 0;color:#8f939c;font-size:11px;line-height:1.45}.security-config-state{border:1px solid #343840;border-radius:999px;padding:3px 7px;font-size:10px;color:#b9bdc6}.security-config-section{border-top:1px solid #292c32;padding-top:12px;margin-top:12px}.security-config-section:first-of-type{border-top:0;margin-top:0;padding-top:0}.security-config-section h4{margin:0 0 9px;font-size:12px}.security-config-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-config-field{display:flex;flex-direction:column;gap:4px}.security-config-field label{font-size:10px;color:#9498a1}.security-config-field input,.security-config-field select{background:#0d0f12;border:1px solid #343840;border-radius:8px;color:#e1e3e7;padding:7px 8px;font-size:11px;min-width:0}.security-config-field input[readonly]{color:#8f939c;background:#111318}.security-config-check{display:flex;align-items:center;gap:7px;font-size:11px;color:#c5c8cf;min-height:32px}.security-config-check input{accent-color:#ddd}.security-config-locked{padding:8px;border:1px dashed #333740;border-radius:8px;color:#8f939c;font-size:10px;line-height:1.45}.security-config-real{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid #343840;border-radius:10px;padding:10px;background:#121418}.security-config-real b{font-size:11px}.security-config-real span{display:block;color:#8f939c;font-size:10px;margin-top:2px}.security-config-real-state{font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace}.security-config-caps{display:flex;gap:8px 12px;flex-wrap:wrap}.security-config-assets{overflow:auto;border:1px solid #30333a;border-radius:10px}.security-config-assets table{width:100%;border-collapse:collapse;min-width:1080px}.security-config-assets th,.security-config-assets td{padding:7px;border-bottom:1px solid #25282e;text-align:left;vertical-align:top;font-size:10px}.security-config-assets th{background:#15171b;color:#8f939c}.security-config-assets input,.security-config-assets select{width:100%;box-sizing:border-box;background:#0d0f12;border:1px solid #343840;border-radius:6px;color:#d9dce2;padding:5px 6px;font-size:10px}.security-config-assets .asset-enabled{width:auto}.security-config-actions{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin-top:14px}.security-config-warning{margin-top:8px;border:1px solid #554a2f;background:#1b1810;border-radius:8px;padding:8px;color:#cabd90;font-size:10px;line-height:1.45}.security-config-audit{max-height:220px;overflow:auto;border:1px solid #30333a;border-radius:9px}.security-config-audit-row{padding:8px;border-bottom:1px solid #26292f;font-size:10px}.security-config-audit-row:last-child{border-bottom:0}.security-config-audit-row b{display:block;color:#c9ccd2;margin-bottom:2px}.security-config-audit-row span{color:#858992}.security-config-empty{padding:14px;text-align:center;color:#747982;font-size:10px}@media(max-width:760px){.security-config-form-grid{grid-template-columns:1fr}.security-config-head{align-items:center}.security-config-real{align-items:flex-start;flex-direction:column}}
"""
html = _replace_once(html, "</style>", config_css + "</style>", "security-config-center-css")

config_markup = r'''
        <div class="security-config-launch">
          <button class="soft-btn" id="securityConfigOpen" type="button">Configure Security Monitoring</button>
          <span class="security-config-note">Admin only · schema validated · atomic save · no network execution on Save</span>
        </div>
        <section class="security-config-center" id="securityConfigCenter" aria-label="Security Configuration Center">
          <div class="security-config-head">
            <div class="security-config-head-copy">
              <h3>Security Configuration Center</h3>
              <p>Configure approved inventory and deterministic read-only monitoring policy. Raw credentials, arbitrary commands, subnet discovery, autonomous remediation and capture execution are not accepted here.</p>
            </div>
            <span class="security-config-state" id="securityConfigState">—</span>
            <button class="soft-btn" id="securityConfigClose" type="button">Close</button>
          </div>

          <div class="security-config-section">
            <h4>General</h4>
            <div class="security-config-form-grid">
              <div class="security-config-check"><input id="securityCfgEnabled" type="checkbox"><label for="securityCfgEnabled">Enable Security Monitoring runtime configuration</label></div>
              <div class="security-config-field"><label for="securityCfgDatabase">Monitoring database path</label><input id="securityCfgDatabase" type="text" autocomplete="off"></div>
              <div class="security-config-field"><label for="securityCfgSecretDirectory">Secret-reference directory</label><input id="securityCfgSecretDirectory" type="text" autocomplete="off"><small class="security-config-note">Only references are stored in inventory. Secret values are never accepted in this form.</small></div>
            </div>
            <div class="security-config-real" style="margin-top:9px">
              <div><b>Approved real-network monitoring</b><span>Only exact enabled assets below can be contacted. This never authorizes subnet scan or arbitrary targets.</span></div>
              <div><span class="security-config-real-state" id="securityCfgRealState">DISABLED</span><button class="soft-btn" id="securityCfgRealToggle" type="button" style="margin-left:8px">Enable…</button></div>
            </div>
          </div>

          <div class="security-config-section">
            <h4>Monitoring Policy</h4>
            <div class="security-config-locked">Locked safety invariants: <b>approved_inventory_only</b> · <b>read_only=true</b> · <b>non_disruptive_v1</b> · bandwidth=<b>counter_only</b> · packet analysis=<b>passive_only</b>. The API rejects attempts to change these invariants.</div>
            <div class="security-config-form-grid" style="margin-top:9px">
              <div class="security-config-field"><label for="securityCfgProfile">Profile ID</label><input id="securityCfgProfile" type="text" autocomplete="off"></div>
              <div class="security-config-check"><input id="securityCfgActiveLiveness" type="checkbox"><label for="securityCfgActiveLiveness">Allow bounded ICMP/TCP liveness for explicitly approved assets</label></div>
              <div class="security-config-field"><label for="securityCfgWorkers">Max workers (1–4)</label><input id="securityCfgWorkers" type="number" min="1" max="4"></div>
              <div class="security-config-field"><label for="securityCfgTimeout">Timeout seconds (0.1–5)</label><input id="securityCfgTimeout" type="number" min="0.1" max="5" step="0.1"></div>
              <div class="security-config-field"><label for="securityCfgRetries">Max retries (0–1)</label><input id="securityCfgRetries" type="number" min="0" max="1"></div>
              <div class="security-config-field"><label for="securityCfgCatchup">Max catch-up runs (0–1)</label><input id="securityCfgCatchup" type="number" min="0" max="1"></div>
            </div>
            <div style="margin-top:9px"><div class="security-config-note" style="margin-bottom:5px">Allowed read-only capabilities</div><div class="security-config-caps" id="securityCfgCapabilities"></div></div>
          </div>

          <div class="security-config-section">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px"><h4 style="margin:0">Approved Assets</h4><button class="soft-btn" id="securityCfgAddAsset" type="button">Add Asset</button></div>
            <div class="security-config-warning">Adding or changing an asset while real-network monitoring is enabled requires the explicit confirmation phrase again. Credential fields accept only typed references such as <code>secret-ref:cisco-cbs250-01</code>; never paste passwords, SNMP auth keys or community strings.</div>
            <div class="security-config-assets" style="margin-top:9px"><table><thead><tr><th>Asset ID</th><th>Role</th><th>Management host</th><th>Capabilities</th><th>TCP ports</th><th>Data class</th><th>Credential reference</th><th>Enabled</th><th></th></tr></thead><tbody id="securityCfgAssetRows"></tbody></table></div>
          </div>

          <div class="security-config-section">
            <h4>Configuration Audit</h4>
            <div class="security-config-audit" id="securityCfgAudit"></div>
          </div>

          <div class="security-config-actions">
            <button class="soft-btn" id="securityCfgReload" type="button">Reload</button>
            <button class="primary-btn" id="securityCfgSave" type="button">Validate &amp; Save</button>
          </div>
        </section>
'''
html = _replace_once(
    html,
    '<div class="security-admin-grid" id="securityAdminGrid"></div>',
    '<div class="security-admin-grid" id="securityAdminGrid"></div>' + config_markup,
    "security-config-center-markup",
)

config_js = r'''
(function(){
const CAPS=['icmp_echo','tcp_connect','snmpv3_read','local_net_read','fixed_readonly_adapter'];
const CONFIRM='ENABLE_APPROVED_REAL_NETWORK_MONITORING';
const q=id=>document.getElementById(id),center=q('securityConfigCenter');
let model=null,original=null,pendingConfirmation='';
function clone(v){return JSON.parse(JSON.stringify(v))}
function text(v){return v===null||v===undefined?'':String(v)}
function csv(v){return String(v||'').split(',').map(x=>x.trim()).filter(Boolean)}
function ints(v){return csv(v).map(x=>Number(x)).filter(x=>Number.isInteger(x))}
async function cfgApi(path,options={}){const response=await fetch(path,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});let body={};try{body=await response.json()}catch(e){}if(!response.ok){const err=new Error(body.error||body.code||('HTTP '+response.status));err.code=body.code||'';throw err}return body}
function setState(label){q('securityConfigState').textContent=label||'—'}
function renderReal(){const enabled=!!(model&&model.allow_real_network);q('securityCfgRealState').textContent=enabled?'ENABLED':'DISABLED';q('securityCfgRealToggle').textContent=enabled?'Disable':'Enable…'}
function renderCaps(){const wrap=q('securityCfgCapabilities');wrap.innerHTML='';const selected=new Set((model.policy&&model.policy.allowed_capabilities)||[]);for(const cap of CAPS){const label=document.createElement('label');label.className='security-config-check';const input=document.createElement('input');input.type='checkbox';input.dataset.capability=cap;input.checked=selected.has(cap);label.append(input,document.createTextNode(cap));wrap.appendChild(label)}}
function assetInput(cls,value,type='text'){const input=document.createElement('input');input.className=cls;input.type=type;if(type==='checkbox')input.checked=!!value;else input.value=text(value);input.autocomplete='off';return input}
function renderAssets(){const body=q('securityCfgAssetRows');body.innerHTML='';const assets=(model&&Array.isArray(model.assets))?model.assets:[];if(!assets.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=9;td.className='security-config-empty';td.textContent='No approved assets. Add an asset before enabling real-network monitoring.';tr.appendChild(td);body.appendChild(tr);return}assets.forEach((asset,index)=>{const tr=document.createElement('tr');tr.dataset.index=String(index);const values=[assetInput('cfg-asset-id',asset.asset_id),assetInput('cfg-asset-role',asset.role),assetInput('cfg-asset-host',asset.management_host),assetInput('cfg-asset-caps',(asset.collector_capabilities||[]).join(', ')),assetInput('cfg-asset-ports',(asset.allowed_tcp_ports||[]).join(', '))];for(const input of values){const td=document.createElement('td');td.appendChild(input);tr.appendChild(td)}const dataTd=document.createElement('td'),sel=document.createElement('select');sel.className='cfg-asset-data';for(const name of ['public','internal','confidential','restricted','secret']){const o=document.createElement('option');o.value=name;o.textContent=name;o.selected=(asset.data_class||'confidential')===name;sel.appendChild(o)}dataTd.appendChild(sel);tr.appendChild(dataTd);const credTd=document.createElement('td');credTd.appendChild(assetInput('cfg-asset-credential',asset.credential_ref||''));tr.appendChild(credTd);const enTd=document.createElement('td'),en=assetInput('asset-enabled',asset.enabled!==false,'checkbox');enTd.appendChild(en);tr.appendChild(enTd);const actionTd=document.createElement('td'),remove=document.createElement('button');remove.type='button';remove.className='soft-btn';remove.textContent='Remove';remove.onclick=()=>{syncAssets();model.assets.splice(index,1);renderAssets()};actionTd.appendChild(remove);tr.appendChild(actionTd);body.appendChild(tr)})}
function syncAssets(){const rows=Array.from(q('securityCfgAssetRows').querySelectorAll('tr[data-index]'));if(!model)return;model.assets=rows.map(tr=>({asset_id:tr.querySelector('.cfg-asset-id').value.trim(),role:tr.querySelector('.cfg-asset-role').value.trim(),management_host:tr.querySelector('.cfg-asset-host').value.trim(),collector_capabilities:csv(tr.querySelector('.cfg-asset-caps').value),allowed_tcp_ports:ints(tr.querySelector('.cfg-asset-ports').value),data_class:tr.querySelector('.cfg-asset-data').value,enabled:tr.querySelector('.asset-enabled').checked,credential_ref:tr.querySelector('.cfg-asset-credential').value.trim()||null}))}
function fill(){q('securityCfgEnabled').checked=!!model.enabled;q('securityCfgDatabase').value=text(model.database_path);q('securityCfgSecretDirectory').value=text(model.secret_directory);q('securityCfgProfile').value=text(model.policy?.profile_id||'default');q('securityCfgActiveLiveness').checked=!!model.policy?.allow_active_liveness;q('securityCfgWorkers').value=text(model.policy?.max_workers??4);q('securityCfgTimeout').value=text(model.policy?.timeout_seconds??3);q('securityCfgRetries').value=text(model.policy?.max_retries??1);q('securityCfgCatchup').value=text(model.policy?.max_catch_up_runs??1);renderReal();renderCaps();renderAssets()}
function collect(){syncAssets();model.enabled=q('securityCfgEnabled').checked;model.database_path=q('securityCfgDatabase').value.trim();model.secret_directory=q('securityCfgSecretDirectory').value.trim()||null;model.policy={...(model.policy||{}),profile_id:q('securityCfgProfile').value.trim(),network_scope:'approved_inventory_only',read_only:true,production_safety_profile:'non_disruptive_v1',allow_active_liveness:q('securityCfgActiveLiveness').checked,bandwidth_measurement_mode:'counter_only',packet_analysis_mode:'passive_only',max_workers:Number(q('securityCfgWorkers').value),timeout_seconds:Number(q('securityCfgTimeout').value),max_retries:Number(q('securityCfgRetries').value),max_catch_up_runs:Number(q('securityCfgCatchup').value),allowed_capabilities:Array.from(q('securityCfgCapabilities').querySelectorAll('input[data-capability]:checked')).map(e=>e.dataset.capability)};return clone(model)}
function needsConfirmation(candidate){const old=original||{},oldPolicy=old.policy||{},newPolicy=candidate.policy||{};const inventoryChanged=JSON.stringify(old.assets||[])!==JSON.stringify(candidate.assets||[]);return (!!newPolicy.allow_active_liveness&&!oldPolicy.allow_active_liveness)||(!!candidate.allow_real_network&&(!old.allow_real_network||inventoryChanged))}
function askConfirmation(){const entered=window.prompt('Type exactly to authorize approved real-network scope:\n\n'+CONFIRM,'');if(entered!==CONFIRM){showToast('Security configuration: confirmation did not match.');return false}pendingConfirmation=CONFIRM;return true}
async function loadAudit(){const box=q('securityCfgAudit');box.innerHTML='';try{const d=await cfgApi('/api/security/config/audit?limit=50');const items=d.items||[];if(!items.length){const e=document.createElement('div');e.className='security-config-empty';e.textContent='No configuration changes recorded yet.';box.appendChild(e);return}for(const item of items){const row=document.createElement('div');row.className='security-config-audit-row';const b=document.createElement('b');b.textContent=(item.recorded_at||'—')+' · '+(item.action||'configuration change');const s=document.createElement('span');s.textContent='actor='+text(item.actor_user_id)+' · changed='+(item.changed_fields||[]).join(', ')+' · assets='+text(item.asset_count)+' · real_network='+text(item.allow_real_network);row.append(b,s);box.appendChild(row)}}catch(e){const d=document.createElement('div');d.className='security-config-empty';d.textContent='Audit unavailable: '+e.message;box.appendChild(d)}}
async function loadConfig(){setState('Loading…');try{const d=await cfgApi('/api/security/config');model=clone(d.config||{});original=clone(d.config||{});pendingConfirmation='';setState((d.config_state||'unknown')+(d.writable?' · writable':' · read-only'));fill();await loadAudit()}catch(e){setState('Unavailable');showToast('Security configuration: '+e.message)}}
q('securityConfigOpen').onclick=()=>{center.classList.add('open');loadConfig()};q('securityConfigClose').onclick=()=>center.classList.remove('open');q('securityCfgReload').onclick=loadConfig;
q('securityCfgAddAsset').onclick=()=>{syncAssets();model.assets=model.assets||[];model.assets.push({asset_id:'',role:'switch',management_host:'',collector_capabilities:['snmpv3_read'],allowed_tcp_ports:[],data_class:'confidential',enabled:true,credential_ref:null});renderAssets()};
q('securityCfgRealToggle').onclick=()=>{if(!model)return;if(model.allow_real_network){model.allow_real_network=false;pendingConfirmation='';renderReal();return}if(!askConfirmation())return;model.allow_real_network=true;renderReal()};
q('securityCfgSave').onclick=async()=>{try{const candidate=collect();if(needsConfirmation(candidate)&&pendingConfirmation!==CONFIRM&&!askConfirmation())return;q('securityCfgSave').disabled=true;setState('Validating…');const d=await cfgApi('/api/security/config',{method:'POST',body:JSON.stringify({config:candidate,confirmation:pendingConfirmation})});model=clone(d.config||candidate);original=clone(model);pendingConfirmation='';fill();setState((d.config_state||'configured')+' · saved');await loadAudit();showToast('Security configuration saved. No network action was executed.')}catch(e){setState('Save rejected');showToast('Security configuration: '+e.message)}finally{q('securityCfgSave').disabled=false}};
})();
'''
html = _replace_once(html, "</body>", f"<script>{config_js}</script></body>", "security-config-center-js")

WORKSPACE_HTML_V15 = html

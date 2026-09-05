from __future__ import annotations


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"WorkSpace frontend canonical patch '{label}' expected exactly one match, got {count}"
        )
    return source.replace(old, new, 1)


def _insert_after_workflow_description(document: str, markup: str) -> str:
    """Insert workflow-draft markup after the stable workflowDescription textarea."""
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


config_markup = (
    '\n'
    '      <div class="security-view" data-security-view="configuration" id="securityConfigView">\n'
    '        <div class="security-config-layout">\n'
    '          <div>\n'
    '            <div class="security-config-panel">\n'
    '              <h3>Monitoring &amp; safety policy</h3>\n'
    '              <div class="security-config-help">Configuration is admin-only. Saving never starts collectors, scans, packet capture, remediation, or shell commands.</div>\n'
    '              <div class="security-config-grid">\n'
    '                <div class="security-switch"><span>Enable monitoring</span><input id="secCfgEnabled" type="checkbox"></div>\n'
    '                <div class="security-switch"><span>Allow approved real-network reads</span><input id="secCfgRealNetwork" type="checkbox"></div>\n'
    '                <div class="security-config-field"><label>Profile ID</label><input id="secCfgProfile" value="default" maxlength="128"></div>\n'
    '                <div class="security-config-field"><label>Max workers (1–4)</label><input id="secCfgWorkers" type="number" min="1" max="4" value="4"></div>\n'
    '                <div class="security-config-field"><label>Timeout seconds (0.1–5)</label><input id="secCfgTimeout" type="number" min="0.1" max="5" step="0.1" value="3"></div>\n'
    '                <div class="security-config-field"><label>Max retries (0–1)</label><input id="secCfgRetries" type="number" min="0" max="1" value="1"></div>\n'
    '                <div class="security-switch wide"><span>Allow active liveness (ICMP/TCP only, never throughput)</span><input id="secCfgActiveLiveness" type="checkbox"></div>\n'
    '              </div>\n'
    '              <div class="security-policy-lock" style="margin-top:9px">Locked safety boundary: approved_inventory_only · read_only · non_disruptive_v1 · counter_only bandwidth · passive_only packet analysis.</div>\n'
    '              <div class="security-config-field wide" style="margin-top:9px"><label>Allowed capabilities</label><div class="security-cap-list" id="secCfgCaps"><label><input type="checkbox" value="snmpv3_read" checked> SNMPv3 read</label><label><input type="checkbox" value="local_net_read" checked> Local telemetry read</label><label><input type="checkbox" value="icmp_echo"> ICMP liveness</label><label><input type="checkbox" value="tcp_connect"> TCP liveness</label></div></div>\n'
    '            </div>\n'
    '\n'
    '            <div class="security-config-panel" style="margin-top:12px">\n'
    '              <h3>Local data &amp; secret boundary</h3>\n'
    '              <div class="security-config-help">Only opaque secret references are stored in monitoring configuration. Passwords, SNMP communities, tokens, auth keys and private keys are rejected by the backend contract.</div>\n'
    '              <div class="security-config-grid">\n'
    '                <div class="security-config-field wide"><label>Monitoring database path</label><input id="secCfgDatabase" autocomplete="off"></div>\n'
    '                <div class="security-config-field wide"><label>Local secret directory</label><input id="secCfgSecretDir" autocomplete="off"></div>\n'
    '              </div>\n'
    '            </div>\n'
    '\n'
    '            <div class="security-config-panel" style="margin-top:12px">\n'
    '              <div class="security-asset-head"><div><h3 style="margin:0">Approved asset inventory</h3><div class="security-config-help" style="margin:3px 0 0">Collectors can target only assets and capabilities explicitly listed here.</div></div><button class="soft-btn" id="secCfgAddAsset" type="button">Add asset</button></div>\n'
    '              <div class="security-assets" id="secCfgAssets"></div>\n'
    '            </div>\n'
    '          </div>\n'
    '\n'
    '          <div>\n'
    '            <div class="security-config-panel">\n'
    '              <h3>Configuration gate</h3>\n'
    '              <div class="security-policy-lock">Fail-closed defaults: monitoring off, real network off, passive packet analysis, no autonomous remediation, no web PCAP execution.</div>\n'
    '              <div class="security-config-actions">\n'
    '                <button class="soft-btn" id="secCfgReload" type="button">Reload</button>\n'
    '                <button class="soft-btn" id="secCfgValidate" type="button">Validate</button>\n'
    '                <button class="soft-btn" id="secCfgReadiness" type="button">Readiness check</button>\n'
    '                <button class="soft-btn" id="secCfgSave" type="button">Save configuration</button>\n'
    '              </div>\n'
    '              <div class="security-config-status" id="secCfgStatus">Open Configuration to load the current policy.</div>\n'
    '              <div class="security-config-meta" id="secCfgMeta"></div>\n'
    '              <div class="security-config-footer-note">Readiness check verifies configuration, local paths and opaque credential references only. It does not probe the network or read secret values.</div>\n'
    '            </div>\n'
    '            <div class="security-config-panel" style="margin-top:12px">\n'
    '              <h3>Recommended telemetry strategy</h3>\n'
    '              <div class="security-config-help">Prefer passive/read-only evidence first: device counters and approved local telemetry. Structured IDS/NSM events can feed the existing event pipeline without granting the AI direct network authority.</div>\n'
    '              <div class="security-kv"><b>Default collection</b><span>SNMPv3 read-only + local telemetry</span></div>\n'
    '              <div class="security-kv" style="margin-top:7px"><b>Packet analysis</b><span>Passive only; incident PCAP requires separate admin approval and dedicated runner</span></div>\n'
    '              <div class="security-kv" style="margin-top:7px"><b>Actions</b><span>Advisory only; no automatic firewall/block/remediation authority</span></div>\n'
    '            </div>\n'
    '          </div>\n'
    '        </div>\n'
    '      </div>\n'
    '\n'
)

config_js = (
    '\n'
    '(function(){\n'
    "const tab=document.getElementById('securityConfigTab'),view=document.getElementById('securityConfigView'),status=document.getElementById('secCfgStatus'),assets=document.getElementById('secCfgAssets'),meta=document.getElementById('secCfgMeta');\n"
    'let loadedEnvelope=null;\n'
    'function cfgText(id){return document.getElementById(id).value.trim()}\n'
    'function cfgBool(id){return !!document.getElementById(id).checked}\n'
    'function cfgNumber(id){return Number(document.getElementById(id).value)}\n'
    "function setStatus(message,ok=null){status.textContent=message;status.style.borderColor=ok===true?'#315a46':ok===false?'#694040':'#30343b'}\n"
    "function metaKV(key,value){const box=document.createElement('div');box.className='security-kv';const b=document.createElement('b');b.textContent=key;const s=document.createElement('span');s.textContent=value===undefined||value===null?'—':String(value);box.append(b,s);meta.appendChild(box)}\n"
    "function selectedCaps(){return Array.from(document.querySelectorAll('#secCfgCaps input:checked')).map(x=>x.value)}\n"
    "function setSelectedCaps(values){const set=new Set(values||[]);for(const x of document.querySelectorAll('#secCfgCaps input'))x.checked=set.has(x.value)}\n"
    'function assetEditor(item={}){const box=document.createElement(\'div\');box.className=\'security-asset-editor\';box.innerHTML=\'<div class="security-asset-head"><b>Approved asset</b><button class="soft-btn secAssetRemove" type="button">Remove</button></div><div class="security-config-grid"><div class="security-config-field"><label>Asset ID</label><input class="secAssetId" maxlength="128"></div><div class="security-config-field"><label>Role</label><input class="secAssetRole" maxlength="64" placeholder="router / switch / server"></div><div class="security-config-field"><label>Management host</label><input class="secAssetHost" maxlength="253" placeholder="192.168.11.1"></div><div class="security-config-field"><label>Data class</label><select class="secAssetClass"><option>public</option><option>internal</option><option selected>confidential</option><option>restricted</option><option>secret</option></select></div><div class="security-switch"><span>Enabled</span><input class="secAssetEnabled" type="checkbox" checked></div><div class="security-config-field"><label>Allowed TCP ports</label><input class="secAssetPorts" placeholder="443, 22"></div><div class="security-config-field wide"><label>Collector capabilities</label><div class="security-cap-list secAssetCaps"><label><input type="checkbox" value="snmpv3_read"> SNMPv3 read</label><label><input type="checkbox" value="local_net_read"> Local read</label><label><input type="checkbox" value="icmp_echo"> ICMP</label><label><input type="checkbox" value="tcp_connect"> TCP connect</label><label><input type="checkbox" value="fixed_readonly_adapter"> Fixed read-only adapter</label></div></div><div class="security-config-field wide"><label>Credential reference (opaque; SNMPv3 only)</label><input class="secAssetCredential" placeholder="secret-ref:router-snmpv3" autocomplete="off"></div></div>\';\n'
    "box.querySelector('.secAssetId').value=item.asset_id||'';box.querySelector('.secAssetRole').value=item.role||'';box.querySelector('.secAssetHost').value=item.management_host||'';box.querySelector('.secAssetClass').value=item.data_class||'confidential';box.querySelector('.secAssetEnabled').checked=item.enabled!==false;box.querySelector('.secAssetPorts').value=(item.allowed_tcp_ports||[]).join(', ');box.querySelector('.secAssetCredential').value=item.credential_ref||'';const caps=new Set(item.collector_capabilities||[]);for(const x of box.querySelectorAll('.secAssetCaps input'))x.checked=caps.has(x.value);box.querySelector('.secAssetRemove').onclick=()=>box.remove();return box}\n"
    "function readAssets(){return Array.from(assets.querySelectorAll('.security-asset-editor')).map(box=>({asset_id:box.querySelector('.secAssetId').value.trim(),role:box.querySelector('.secAssetRole').value.trim(),management_host:box.querySelector('.secAssetHost').value.trim(),collector_capabilities:Array.from(box.querySelectorAll('.secAssetCaps input:checked')).map(x=>x.value),allowed_tcp_ports:box.querySelector('.secAssetPorts').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number),data_class:box.querySelector('.secAssetClass').value,enabled:box.querySelector('.secAssetEnabled').checked,credential_ref:box.querySelector('.secAssetCredential').value.trim()||null}))}\n"
    "function currentPayload(){return {enabled:cfgBool('secCfgEnabled'),allow_real_network:cfgBool('secCfgRealNetwork'),database_path:cfgText('secCfgDatabase'),secret_directory:cfgText('secCfgSecretDir')||null,policy:{profile_id:cfgText('secCfgProfile'),network_scope:'approved_inventory_only',read_only:true,production_safety_profile:'non_disruptive_v1',allow_active_liveness:cfgBool('secCfgActiveLiveness'),bandwidth_measurement_mode:'counter_only',packet_analysis_mode:'passive_only',max_workers:cfgNumber('secCfgWorkers'),timeout_seconds:cfgNumber('secCfgTimeout'),max_retries:cfgNumber('secCfgRetries'),max_catch_up_runs:1,allowed_capabilities:selectedCaps()},assets:readAssets()}}\n"
    "function fill(payload){document.getElementById('secCfgEnabled').checked=!!payload.enabled;document.getElementById('secCfgRealNetwork').checked=!!payload.allow_real_network;document.getElementById('secCfgDatabase').value=payload.database_path||'';document.getElementById('secCfgSecretDir').value=payload.secret_directory||'';const p=payload.policy||{};document.getElementById('secCfgProfile').value=p.profile_id||'default';document.getElementById('secCfgWorkers').value=p.max_workers??4;document.getElementById('secCfgTimeout').value=p.timeout_seconds??3;document.getElementById('secCfgRetries').value=p.max_retries??1;document.getElementById('secCfgActiveLiveness').checked=!!p.allow_active_liveness;setSelectedCaps(p.allowed_capabilities||['snmpv3_read','local_net_read']);assets.innerHTML='';for(const item of payload.assets||[])assets.appendChild(assetEditor(item))}\n"
    "function renderEnvelope(d){loadedEnvelope=d;fill(d.config||{});meta.innerHTML='';metaKV('State',d.state);metaKV('Config path',d.config_path);metaKV('Path source',d.path_source);metaKV('Policy fingerprint',d.summary?.policy_fingerprint);setStatus(d.state==='configured'?'Configuration loaded.':'Safe defaults loaded but not saved.',true)}\n"
    "async function loadConfig(){try{setStatus('Loading configuration…');renderEnvelope(await api('/api/security/config'))}catch(e){setStatus('Load failed: '+e.message,false)}}\n"
    "async function postConfig(path,payload){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(payload)});let d={};try{d=await r.json()}catch(e){}if(!r.ok)throw new Error(d.error||d.code||('HTTP '+r.status));return d}\n"
    "async function validateConfig(){try{setStatus('Validating…');const d=await postConfig('/api/security/config/validate',{config:currentPayload()});setStatus('VALID\\nPolicy: '+d.summary.policy_fingerprint+'\\nAssets: '+d.summary.asset_count+'\\nReady: '+d.readiness.ready,true)}catch(e){setStatus('INVALID\\n'+e.message,false)}}\n"
    "async function readiness(){try{setStatus('Checking local readiness…');const d=await postConfig('/api/security/config/readiness',{});const lines=['Ready: '+d.ready,'Network test executed: '+d.network_test_executed,'Secret values read: '+d.secret_values_read];for(const x of d.issues||[])lines.push('BLOCKER '+x.code+': '+x.message);for(const x of d.warnings||[])lines.push('WARNING '+x.code+': '+x.message);setStatus(lines.join('\\n'),d.ready)}catch(e){setStatus('Readiness failed: '+e.message,false)}}\n"
    "async function saveConfig(){const payload=currentPayload();if(payload.policy.allow_active_liveness&&!confirm('Active liveness generates ICMP/TCP probe traffic to explicitly approved inventory only. Continue saving?'))return;if(payload.allow_real_network&&!confirm('Allow read-only network collection for explicitly approved assets? Saving does not start collection.'))return;try{setStatus('Validating and saving…');const d=await postConfig('/api/security/config/save',{config:payload});setStatus('SAVED\\nPolicy: '+d.summary.policy_fingerprint+'\\nReady: '+d.readiness.ready,true);await loadConfig();if(typeof refreshSecurityBadge==='function')refreshSecurityBadge()}catch(e){setStatus('SAVE BLOCKED\\n'+e.message,false)}}\n"
    "function openConfig(){if(state.session?.role!=='admin'){showToast('Administrator role required');return}for(const b of document.querySelectorAll('[data-security-tab]'))b.classList.toggle('active',b===tab);for(const v of document.querySelectorAll('[data-security-view]'))v.classList.toggle('active',v===view);loadConfig()}\n"
    "function updateAccess(){tab.classList.toggle('hidden',state.session?.role!=='admin')}\n"
    "tab.onclick=openConfig;document.getElementById('secCfgAddAsset').onclick=()=>assets.appendChild(assetEditor());document.getElementById('secCfgReload').onclick=loadConfig;document.getElementById('secCfgValidate').onclick=validateConfig;document.getElementById('secCfgReadiness').onclick=readiness;document.getElementById('secCfgSave').onclick=saveConfig;document.getElementById('securityAnalystBtn').addEventListener('click',updateAccess);document.getElementById('loginBtn').addEventListener('click',()=>setTimeout(updateAccess,500));updateAccess();\n"
    '})();\n'
)

WORKSPACE_HTML = (
    '<!doctype html>\n'
    '<html lang="en">\n'
    '<head>\n'
    '<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    '<title>WorkSpace</title>\n'
    '<style>\n'
    ':root{\n'
    '  color-scheme:dark;\n'
    '  --bg:#08090b;--panel:#17181b;--panel2:#202124;--panel3:#292a2e;\n'
    '  --line:#303238;--line2:#444750;--text:#f2f3f5;--muted:#9b9ea5;\n'
    '  --accent:#5b7cfa;--danger:#ff9696;--ok:#75d49a;--sidebar-w:286px;\n'
    '  --shadow:0 18px 55px rgba(0,0,0,.42)\n'
    '}\n'
    '*{box-sizing:border-box}\n'
    'html,body{height:100%}\n'
    'body{margin:0;background:radial-gradient(circle at 52% 18%,#11131a 0,#090a0d 35%,#07080a 72%);color:var(--text);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow:hidden}\n'
    'button,select,textarea,input{font:inherit}button{color:inherit}.hidden{display:none!important}\n'
    'svg{stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}\n'
    '\n'
    '.sidebar{position:fixed;left:0;top:0;bottom:0;width:286px;background:#050506;border-right:1px solid #1d1e21;z-index:15;display:flex;flex-direction:column;transition:width .18s ease;overflow:hidden}\n'
    '.sidebar.collapsed{width:70px}\n'
    '.sidebar-top{height:68px;display:flex;align-items:center;padding:0 13px;gap:9px;flex:0 0 auto}\n'
    '.workspace-logo{display:flex;align-items:center;gap:10px;min-width:0;font-weight:700;font-size:18px;letter-spacing:-.02em;flex:1}\n'
    '.logo-mark{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;flex:0 0 auto;background:linear-gradient(145deg,#1c2030,#101116);border:1px solid #34384d;color:#dfe4ff}\n'
    '.logo-mark svg{width:23px;height:23px}\n'
    '.logo-text{white-space:nowrap;overflow:hidden;transition:opacity .12s}\n'
    '.sidebar.collapsed .logo-text{opacity:0;width:0}\n'
    '.sidebar-toggle{width:36px;height:36px;border:0;background:transparent;border-radius:10px;display:grid;place-items:center;cursor:pointer;color:#c7c9ce;flex:0 0 auto}\n'
    '.sidebar-toggle:hover,.side-action:hover,.account-btn:hover{background:#17181b}\n'
    '.sidebar-toggle svg{width:20px;height:20px}\n'
    '.sidebar.collapsed .sidebar-toggle{position:absolute;left:17px;top:79px}\n'
    '\n'
    '.side-nav{padding:5px 9px;display:flex;flex-direction:column;gap:2px;flex:0 0 auto}\n'
    '.side-action{height:44px;width:100%;border:0;background:transparent;border-radius:10px;display:flex;align-items:center;gap:11px;padding:0 11px;cursor:pointer;text-align:left;color:#ececef;white-space:nowrap}\n'
    '.side-action svg{width:21px;height:21px;flex:0 0 auto}.side-action span{overflow:hidden;text-overflow:ellipsis}\n'
    '.sidebar.collapsed .side-nav{padding-top:53px}\n'
    '.sidebar.collapsed .side-action{width:52px;justify-content:center;padding:0;margin:auto}.sidebar.collapsed .side-action span{display:none}\n'
    '\n'
    '.history-search{margin:5px 12px 4px;position:relative}\n'
    '.history-search input{width:100%;height:37px;background:#111215;border:1px solid #292b30;color:#e7e8eb;border-radius:10px;padding:0 34px 0 11px;outline:0}\n'
    '.history-search input:focus{border-color:#50566f}.history-search button{position:absolute;right:4px;top:4px;width:29px;height:29px;border:0;background:transparent;border-radius:8px;display:grid;place-items:center;cursor:pointer;color:#92959c}\n'
    '.history-search button svg{width:16px;height:16px}.sidebar.collapsed .history-search{display:none}\n'
    '\n'
    '.history-scroll{flex:1;overflow:auto;padding:6px 9px 12px;scrollbar-width:thin;scrollbar-color:#2d2f34 transparent}\n'
    '.history-section{margin-top:13px}.history-heading{font-size:12px;font-weight:650;color:#878a90;padding:4px 10px 7px;white-space:nowrap}\n'
    '.history-empty{font-size:12px;color:#676a70;padding:8px 10px}\n'
    '.conversation-row{height:39px;border-radius:9px;display:flex;align-items:center;gap:7px;padding:0 6px 0 10px;cursor:pointer;color:#dfe0e3;position:relative}\n'
    '.conversation-row:hover,.conversation-row.active{background:#18191c}.conversation-row.active{color:#fff}\n'
    '.conversation-icon{width:18px;height:18px;flex:0 0 auto;color:#b9bbc1}.conversation-icon svg{width:18px;height:18px}\n'
    '.conversation-title{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}\n'
    '.pin-btn{width:28px;height:28px;border:0;background:transparent;border-radius:8px;display:grid;place-items:center;cursor:pointer;color:#8f9298;opacity:0}\n'
    '.conversation-row:hover .pin-btn,.conversation-row.active .pin-btn{opacity:1}.pin-btn.pinned{opacity:1;color:#d4d8ff}.pin-btn:hover{background:#26272b}.pin-btn svg{width:15px;height:15px}\n'
    '.sidebar.collapsed .history-scroll{display:none}\n'
    '\n'
    '.account-wrap{border-top:1px solid #1d1e21;padding:9px;position:relative;flex:0 0 auto}\n'
    '.account-btn{width:100%;height:53px;border:0;background:transparent;border-radius:11px;display:flex;align-items:center;gap:10px;padding:0 9px;cursor:pointer;text-align:left}\n'
    '.account-avatar{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto;background:#202449;border:1px solid #4b53a4;font-weight:700;font-size:13px;position:relative}\n'
    '.account-avatar::after{content:"";position:absolute;right:-1px;bottom:0;width:8px;height:8px;border-radius:50%;background:#4bd384;border:2px solid #050506}\n'
    '.account-copy{min-width:0;flex:1}.account-name{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.account-sub{font-size:11px;color:#888b91;white-space:nowrap}\n'
    '.account-more{color:#898c92}.account-more svg{width:18px;height:18px}\n'
    '.sidebar.collapsed .account-btn{width:52px;justify-content:center;padding:0;margin:auto}.sidebar.collapsed .account-copy,.sidebar.collapsed .account-more{display:none}\n'
    '.account-menu{position:absolute;left:10px;right:10px;bottom:69px;background:#202125;border:1px solid #3a3c43;border-radius:14px;padding:7px;box-shadow:var(--shadow);display:none}\n'
    '.account-menu.open{display:block}.account-menu button{width:100%;height:39px;border:0;background:transparent;border-radius:9px;text-align:left;padding:0 11px;cursor:pointer}.account-menu button:hover{background:#2b2c31}\n'
    '.sidebar.collapsed .account-menu{left:68px;right:auto;width:210px;bottom:10px}\n'
    '\n'
    '.main-shell{height:100vh;margin-left:286px;transition:margin-left .18s ease;display:flex;flex-direction:column}\n'
    'body.sidebar-collapsed .main-shell{margin-left:70px}\n'
    '.topbar{height:68px;display:flex;align-items:center;padding:0 24px;border-bottom:1px solid rgba(36,38,43,.45);flex:0 0 auto}\n'
    '.mobile-menu{display:none}.conversation-name{font-weight:600;color:#e9eaed;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.top-spacer{flex:1}\n'
    '.security-badge{font-size:11px;color:#777b83;border:1px solid #292b31;border-radius:999px;padding:5px 9px}\n'
    '\n'
    '#messages{flex:1;overflow:auto;padding:26px 18px 230px;scrollbar-width:thin;scrollbar-color:#34363c transparent}\n'
    '.empty-state{height:62vh;display:flex;align-items:center;justify-content:center;color:#777a81;text-align:center}\n'
    '.empty-inner{max-width:440px}.empty-logo{width:50px;height:50px;border-radius:16px;margin:0 auto 14px;display:grid;place-items:center;background:#14161d;border:1px solid #2b2f42;color:#cdd6ff}.empty-logo svg{width:30px;height:30px}.empty-title{color:#cfd1d6;font-weight:600;font-size:18px}.empty-sub{font-size:13px;margin-top:6px}\n'
    '.msg{max-width:900px;margin:0 auto 24px;word-break:break-word}.who{font-size:12px;color:var(--muted);margin:0 0 6px 4px}.bubble{padding:17px 19px;border:1px solid var(--line);border-radius:18px;background:rgba(24,25,29,.92)}.user .bubble{background:#202226;white-space:pre-wrap;margin-left:auto;max-width:80%}.error .bubble{border-color:#784b50;color:#ffd0d0}\n'
    '.report h1{font-size:24px;margin:0 0 14px}.report h2{font-size:17px;margin:22px 0 8px}.report p{margin:7px 0}.report ul{padding-left:22px}.report li{margin:5px 0}.report blockquote{margin:10px 0;padding:9px 12px;border-left:3px solid var(--accent);background:#171b27;color:#dce3ff}.report hr{border:0;border-top:1px solid var(--line);margin:20px 0}\n'
    '.stages{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px}.stage{border:1px solid var(--line);border-radius:12px;padding:9px 10px;font-size:12px;background:#111216}.stage b{display:block}.stage small{color:var(--muted)}.stage.completed{border-color:#386249}.stage.running{border-color:#4c5d97}.stage.blocked,.stage.failed{border-color:#75474c}.stage.skipped{opacity:.55}\n'
    '.answerTools,.downloads{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.answerTools button,.downloads a,.tech a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:#24262b;border-radius:9px;padding:6px 10px;font-size:12px}.downloads a.primaryFile{background:#e8e9ed;color:#111216;border-color:#e8e9ed;font-weight:700}.tech{margin-top:10px;border:1px solid var(--line);border-radius:10px;padding:8px 10px;color:var(--muted)}.tech summary{cursor:pointer}.tech a{display:inline-block;margin:7px 7px 2px 0}\n'
    '\n'
    '.composer-wrap{position:fixed;left:286px;right:0;bottom:0;padding:48px 18px 22px;background:linear-gradient(transparent,rgba(8,9,11,.94) 24%,var(--bg) 54%);z-index:8;pointer-events:none;transition:left .18s ease}\n'
    'body.sidebar-collapsed .composer-wrap{left:70px}.composer-area{max-width:940px;margin:auto;position:relative;pointer-events:auto}.disclaimer{text-align:center;color:#74777e;font-size:12px;margin-bottom:11px}.composer{border:1px solid var(--line2);background:rgba(31,32,36,.96);border-radius:32px;box-shadow:0 14px 42px rgba(0,0,0,.28);display:flex;align-items:flex-end;gap:8px;padding:9px 10px;min-height:64px}\n'
    '.circle-btn{width:46px;height:46px;border:1px solid #44474e;border-radius:50%;background:#242529;display:grid;place-items:center;cursor:pointer;flex:0 0 auto}.circle-btn:hover{background:#2b2d32}.circle-btn svg{width:23px;height:23px}#input{flex:1;border:0;background:transparent;color:var(--text);outline:0;resize:none;min-height:46px;max-height:170px;padding:11px 6px 8px;line-height:1.55}#input::placeholder{color:#a5a7ad}\n'
    '.composer-actions{display:flex;align-items:center;gap:5px}.effort-select{appearance:none;border:0;background:transparent;color:#d7d8dc;padding:12px 28px 12px 10px;outline:0;cursor:pointer;background-image:linear-gradient(45deg,transparent 50%,#aaa 50%),linear-gradient(135deg,#aaa 50%,transparent 50%);background-position:calc(100% - 14px) 19px,calc(100% - 9px) 19px;background-size:5px 5px,5px 5px;background-repeat:no-repeat}.vline{width:1px;height:32px;background:#383a40;margin:0 3px}#sendBtn{background:var(--accent);border-color:var(--accent);color:#fff}#sendBtn:hover{background:#6c88ff}#sendBtn:disabled{opacity:.45;cursor:not-allowed}#micBtn[aria-disabled="true"]{color:#a6a8ad}\n'
    '.mode-pill{position:absolute;left:68px;bottom:72px;display:none;align-items:center;gap:8px;border:1px solid #3b4262;background:#1a1d28;border-radius:999px;padding:6px 10px;color:#cfd8ff;font-size:12px}.mode-pill.visible{display:flex}.mode-pill button{border:0;background:transparent;color:#aab8ef;cursor:pointer;padding:0}.attachments{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 9px 10px}.chip{display:flex;align-items:center;gap:6px;max-width:260px;border:1px solid #3a3d45;background:#1c1e22;border-radius:10px;padding:6px 8px;color:#d9dadd;font-size:12px}.chip span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.chip button{border:0;background:transparent;color:#8f9299;padding:0 2px;cursor:pointer}\n'
    '\n'
    '.plus-menu{position:absolute;left:0;bottom:76px;width:min(430px,calc(100vw - 36px));background:rgba(32,33,36,.99);border:1px solid #45474d;border-radius:22px;padding:8px;box-shadow:var(--shadow);display:none;z-index:20;overflow:hidden}.plus-menu.open{display:block}.menu-row{width:100%;border:0;background:transparent;color:var(--text);display:grid;grid-template-columns:42px 1fr auto;gap:8px;align-items:center;text-align:left;padding:11px 12px;border-radius:14px;cursor:pointer}.menu-row:hover{background:#2a2b2f}.menu-row.disabled{opacity:.45;cursor:default}.menu-row.disabled:hover{background:transparent}.menu-icon{width:30px;height:30px;display:grid;place-items:center;color:#8ba0ff}.menu-icon.green{color:#69d7a5}.menu-icon.blue{color:#5cb4ff}.menu-icon.purple{color:#9c83ff}.menu-icon.white{color:#e5e5e7}.menu-icon svg{width:24px;height:24px}.menu-title{font-size:14px}.menu-sub{font-size:12px;color:#a1a4aa}.menu-state{font-size:11px;color:#9fa3ac}.menu-divider{height:1px;background:#3a3c42;margin:5px 10px}.menu-options{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:8px 10px 10px}.menu-options label{font-size:11px;color:#90939a}.menu-options select{width:100%;margin-top:4px;background:#292b30;color:#e7e8ea;border:1px solid #41444c;border-radius:9px;padding:7px}\n'
    '\n'
    '.library-modal{position:fixed;inset:0;background:rgba(0,0,0,.58);z-index:30;display:none;align-items:center;justify-content:center;padding:20px}.library-modal.open{display:flex}.library-card{width:min(680px,96vw);max-height:76vh;display:flex;flex-direction:column;background:#1b1c20;border:1px solid #44474f;border-radius:20px;box-shadow:var(--shadow)}.library-head{display:flex;align-items:center;padding:16px 18px;border-bottom:1px solid #36383f}.library-head h2{font-size:17px;margin:0}.library-head button{margin-left:auto}.library-list{overflow:auto;padding:8px}.library-empty{padding:30px;color:var(--muted);text-align:center}.library-item{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:10px;border-radius:12px}.library-item:hover{background:#24262b}.library-item input{width:16px;height:16px}.library-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.library-meta{font-size:11px;color:#92959c}.library-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 16px;border-top:1px solid #36383f}\n'
    '.soft-btn{border:1px solid #41444b;background:#26282d;border-radius:10px;padding:8px 12px;cursor:pointer}.soft-btn.primary{background:#e8e9ed;color:#111;border-color:#e8e9ed;font-weight:650}.toast{position:fixed;left:calc(50% + 143px);bottom:122px;transform:translateX(-50%);background:#292b30;border:1px solid #484b53;border-radius:12px;padding:9px 13px;color:#e5e6e9;font-size:12px;z-index:40;box-shadow:var(--shadow);opacity:0;pointer-events:none;transition:.18s}body.sidebar-collapsed .toast{left:calc(50% + 35px)}.toast.show{opacity:1}\n'
    '#login{position:fixed;inset:0;background:#090a0c;z-index:50;display:flex;align-items:center;justify-content:center}.login-card{width:min(420px,90vw);background:#191a1e;border:1px solid #3b3d44;border-radius:20px;padding:25px;box-shadow:var(--shadow)}.login-card h2{margin:0 0 6px}.login-card p{color:var(--muted)}.login-card input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:11px;padding:11px 12px;margin:6px 0 12px;outline:0}.login-card button{width:100%}.login-error{color:var(--danger);font-size:12px}.user-admin-card{width:min(820px,96vw);max-height:84vh}.user-admin-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;padding:14px 16px;border-bottom:1px solid #36383f}.user-admin-form input,.user-admin-form select,.password-form input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:9px;padding:9px 10px;outline:0}.user-admin-form .wide{grid-column:1/-1}.user-admin-users{overflow:auto;padding:8px 12px 14px}.user-admin-row{display:grid;grid-template-columns:minmax(150px,1.2fr) minmax(120px,1fr) 100px 82px auto;gap:8px;align-items:center;padding:10px;border-bottom:1px solid #2e3035}.user-admin-row input,.user-admin-row select{min-width:0;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:8px;padding:7px}.user-admin-name{font-weight:650;overflow:hidden;text-overflow:ellipsis}.user-admin-meta{font-size:11px;color:var(--muted)}.password-form{display:grid;gap:10px;padding:16px}@media(max-width:760px){.user-admin-form{grid-template-columns:1fr}.user-admin-form .wide{grid-column:auto}.user-admin-row{grid-template-columns:1fr 92px}.user-admin-row .user-admin-profile{grid-column:1/-1}}\n'
    '\n'
    '@media(max-width:760px){\n'
    '  .sidebar{width:286px;box-shadow:18px 0 45px rgba(0,0,0,.35)}.sidebar.collapsed{width:0;border:0}.sidebar.collapsed .sidebar-top,.sidebar.collapsed .side-nav,.sidebar.collapsed .account-wrap{display:none}\n'
    '  .main-shell,body.sidebar-collapsed .main-shell{margin-left:0}.composer-wrap,body.sidebar-collapsed .composer-wrap{left:0}.mobile-menu{display:grid;width:38px;height:38px;border:0;background:transparent;border-radius:10px;place-items:center;margin-right:8px}.mobile-menu:hover{background:#18191c}.mobile-menu svg{width:21px;height:21px}.security-badge{display:none}\n'
    '  .stages{grid-template-columns:1fr}.user .bubble{max-width:92%}.menu-options{grid-template-columns:1fr}.toast,body.sidebar-collapsed .toast{left:50%}\n'
    '}\n'
    '\n'
    '.conversation-more-btn{width:28px;height:28px;border:0;background:transparent;border-radius:8px;display:grid;place-items:center;cursor:pointer;color:#9a9da4;opacity:0;flex:0 0 auto}.conversation-row:hover .conversation-more-btn,.conversation-row.active .conversation-more-btn{opacity:1}.conversation-more-btn:hover{background:#26272b}.conversation-more-btn svg{width:17px;height:17px}.side-action.selected{background:#17181b;color:#fff}.history-time-heading{font-size:11px;font-weight:650;color:#73767d;padding:9px 10px 4px}.archive-indicator{font-size:9px;color:#858992;border:1px solid #353840;border-radius:999px;padding:1px 5px;flex:0 0 auto}.conversation-menu{position:fixed;width:190px;background:#202125;border:1px solid #3a3c43;border-radius:13px;padding:6px;box-shadow:var(--shadow);display:none;z-index:60}.conversation-menu.open{display:block}.conversation-menu button{width:100%;height:38px;border:0;background:transparent;border-radius:8px;text-align:left;padding:0 10px;cursor:pointer}.conversation-menu button:hover{background:#2b2c31}.conversation-menu button.danger{color:#ffaaaa}.conversation-menu button.danger:hover{background:#382126}.conversation-dialog{width:min(460px,96vw)}.conversation-dialog-body{padding:16px}.conversation-dialog-body input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:10px;padding:10px 11px;outline:0}.conversation-dialog-copy{color:#b4b6bc;margin:0 0 14px}.dialog-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}.soft-btn.danger{background:#8a343a;border-color:#9b4349;color:#fff}.soft-btn.danger:hover{background:#9b3c43}#input:disabled{opacity:.58;cursor:not-allowed}\n'
    '\n'
    '.projects-heading{display:flex;align-items:center;gap:6px}.projects-heading span{flex:1}.project-add-btn,.project-more-btn{width:27px;height:27px;border:0;background:transparent;border-radius:7px;display:grid;place-items:center;cursor:pointer;color:#92959c}.project-add-btn:hover,.project-more-btn:hover{background:#24262b;color:#fff}.project-add-btn svg,.project-more-btn svg{width:16px;height:16px}.project-row{height:38px;border-radius:9px;display:flex;align-items:center;gap:8px;padding:0 5px 0 10px;cursor:pointer;color:#dfe0e3}.project-row:hover,.project-row.active{background:#18191c}.project-folder{width:18px;height:18px;color:#b9bbc1;flex:0 0 auto}.project-folder svg{width:18px;height:18px}.project-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}.project-count{font-size:10px;color:#73767d}.project-more-btn{opacity:0}.project-row:hover .project-more-btn,.project-row.active .project-more-btn{opacity:1}.project-menu{position:fixed;width:170px;background:#202125;border:1px solid #3a3c43;border-radius:13px;padding:6px;box-shadow:var(--shadow);display:none;z-index:61}.project-menu.open{display:block}.project-menu button{width:100%;height:38px;border:0;background:transparent;border-radius:8px;text-align:left;padding:0 10px;cursor:pointer}.project-menu button:hover{background:#2b2c31}.project-menu button.danger{color:#ffaaaa}.project-menu button.danger:hover{background:#382126}.move-project-list{max-height:320px;overflow:auto;padding:8px}.move-project-row{width:100%;display:flex;align-items:center;gap:9px;border:0;background:transparent;color:#e5e6e9;padding:10px 11px;border-radius:10px;cursor:pointer;text-align:left}.move-project-row:hover,.move-project-row.selected{background:#292b30}.move-project-row svg{width:19px;height:19px}.project-context{font-size:11px;color:#858992;margin-left:7px}.sidebar.collapsed #projectsSection{display:none}\n'
    '\n'
    ".login-divider{display:flex;align-items:center;gap:10px;margin:14px 0;color:#767982;font-size:12px}.login-divider:before,.login-divider:after{content:'';height:1px;background:#34363d;flex:1}.external-login-list{display:grid;gap:8px}.external-login-btn{height:42px;display:flex!important;align-items:center;justify-content:center;gap:9px;background:#24262b!important;border:1px solid #41434a!important}.external-login-btn:hover{background:#2c2e34!important}.external-login-btn.hidden,.login-divider.hidden{display:none!important}.external-login-note{font-size:11px;color:#7f828a;margin-top:10px;line-height:1.4}.external-admin{border-top:1px solid #36383f;padding:12px 16px}.external-admin h3{font-size:13px;margin:0 0 8px}.external-identity-row{display:grid;grid-template-columns:110px minmax(130px,1fr) minmax(150px,1fr) auto;gap:8px;align-items:center;padding:9px 0;border-bottom:1px solid #2e3035}.external-provider{text-transform:capitalize;font-weight:650}.external-identity-row select{min-width:0;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:8px;padding:7px}.external-status{font-size:11px;color:var(--muted)}.external-actions{display:flex;gap:6px}.external-actions button{white-space:nowrap}@media(max-width:760px){.external-identity-row{grid-template-columns:1fr 1fr}.external-actions{grid-column:1/-1}}\n"
    '\n'
    '.workflow-studio-btn{position:fixed;right:18px;bottom:18px;z-index:40;border:1px solid #474a52;background:#24262b;color:var(--text);border-radius:999px;padding:10px 15px;font-weight:650;box-shadow:0 8px 28px rgba(0,0,0,.28);cursor:pointer}.workflow-studio-btn:hover{background:#303239}.workflow-studio-overlay{position:fixed;inset:0;z-index:80;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;padding:20px}.workflow-studio-overlay.open{display:flex}.workflow-studio-panel{width:min(1180px,96vw);max-height:92vh;overflow:auto;background:#1d1f23;border:1px solid #41434a;border-radius:16px;padding:18px;box-shadow:0 24px 80px rgba(0,0,0,.48)}.workflow-studio-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.workflow-studio-head h2{font-size:18px;margin:0}.workflow-studio-note{font-size:12px;color:var(--muted);margin:5px 0 14px}.workflow-studio-input{width:100%;min-height:118px;resize:vertical;background:#151619;color:var(--text);border:1px solid #3b3d43;border-radius:10px;padding:12px;font:inherit;box-sizing:border-box}.workflow-studio-actions{display:flex;gap:8px;align-items:center;margin:10px 0 14px;flex-wrap:wrap}.workflow-chip{font-size:11px;border:1px solid #3f4249;border-radius:999px;padding:4px 8px;color:var(--muted)}.workflow-grid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(280px,.65fr);gap:14px}.workflow-card{background:#17181b;border:1px solid #33363c;border-radius:12px;padding:12px;min-width:0}.workflow-card h3{font-size:13px;margin:0 0 9px}.workflow-diagram{overflow:auto;min-height:260px;color:#d8dae0}.workflow-diagram svg{display:block;min-width:520px;max-width:100%;height:auto}.workflow-code{white-space:pre;overflow:auto;max-height:300px;background:#101114;border-radius:8px;padding:10px;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.workflow-step{border-left:2px solid #454851;padding:7px 9px;margin:6px 0}.workflow-step strong{display:block;font-size:12px}.workflow-step span{font-size:11px;color:var(--muted)}.workflow-warning{font-size:11px;color:#d9b45c;margin-top:5px}.workflow-tabs{display:flex;gap:6px;margin-bottom:8px}.workflow-tabs button{font-size:11px}.workflow-hidden{display:none!important}@media(max-width:820px){.workflow-grid{grid-template-columns:1fr}.workflow-studio-panel{padding:14px}.workflow-studio-btn{right:12px;bottom:12px}}\n'
    '\n'
    '.workflow-v4-box{margin-top:12px;padding:11px;border:1px solid #3a3d44;border-radius:10px;background:#131417}.workflow-v4-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.workflow-v4-detail{font-size:11px;color:var(--muted);margin-top:7px;word-break:break-word}.workflow-v4-ok{color:#79c98a}.workflow-v4-paused{color:#e0b85e}.workflow-v4-blocked{color:#e08a60}.workflow-v4-danger{border-color:#7c4b4b!important}.workflow-v4-danger:hover{background:#4a2727!important}.workflow-v4-input{width:230px;max-width:60vw;background:#151619;color:var(--text);border:1px solid #3b3d43;border-radius:8px;padding:7px 9px;font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.workflow-v4-separator{width:1px;height:24px;background:#36383e;margin:0 2px}@media(max-width:720px){.workflow-v4-separator{display:none}.workflow-v4-input{width:100%;max-width:none}}\n'
    '\n'
    '.specialized-section{padding:8px 9px 5px;flex:0 0 auto;border-top:1px solid #151619}.specialized-heading{padding:3px 10px 6px;color:#666a72;font-size:10px;font-weight:750;letter-spacing:.08em}.security-specialized-btn{position:relative}.security-specialized-badge{margin-left:auto;max-width:86px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border:1px solid #343840;border-radius:999px;padding:2px 6px;color:#aeb3bd;font-size:9px}.sidebar.collapsed .specialized-heading{display:none}.sidebar.collapsed .specialized-section{padding:4px 9px}.sidebar.collapsed .security-specialized-btn{width:52px;justify-content:center;padding:0;margin:auto}.sidebar.collapsed .security-specialized-btn .security-label,.sidebar.collapsed .security-specialized-badge{display:none}\n'
    '.security-surface{display:none;flex:1;min-height:0;overflow:auto;padding:22px 24px 42px;background:radial-gradient(circle at 48% 0,#10141b 0,#090b0f 36%,#08090b 78%)}.security-surface.open{display:block}body.security-analyst-open #messages{display:none}body.security-analyst-open .composer-wrap{display:none}.security-shell{max-width:1240px;margin:0 auto}.security-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:14px}.security-head-copy{flex:1}.security-head h2{margin:0;font-size:22px}.security-sub{color:var(--muted);font-size:12px;margin-top:4px}.security-status-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.security-status-chip{border:1px solid #363a42;border-radius:999px;padding:4px 8px;font-size:10px;color:#b9bdc6}.security-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 14px}.security-tab{border:1px solid #373a42;background:#17191e;color:#cdd0d6;border-radius:9px;padding:7px 10px;cursor:pointer;font-size:12px}.security-tab.active{background:#e7e9ee;color:#111318;border-color:#e7e9ee}.security-view{display:none}.security-view.active{display:block}.security-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.security-card{border:1px solid #30333a;background:#14161a;border-radius:12px;padding:12px;min-width:0}.security-card-label{font-size:10px;color:#81858e;text-transform:uppercase;letter-spacing:.05em}.security-card-value{font-size:20px;font-weight:720;margin-top:3px;overflow:hidden;text-overflow:ellipsis}.security-table-wrap{overflow:auto;border:1px solid #30333a;border-radius:12px;background:#111317}.security-table{width:100%;border-collapse:collapse;min-width:760px}.security-table th,.security-table td{padding:9px 10px;border-bottom:1px solid #282b31;text-align:left;font-size:11px;vertical-align:top}.security-table th{color:#8f939c;font-weight:650;background:#15171b;position:sticky;top:0}.security-table tr.clickable{cursor:pointer}.security-table tr.clickable:hover{background:#1b1e24}.security-empty{padding:28px;color:#777b84;text-align:center}.security-pager{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:9px}.security-pager span{font-size:10px;color:#858992}.security-detail{margin-top:12px;border:1px solid #30333a;border-radius:12px;background:#101216;padding:11px;white-space:pre-wrap;word-break:break-word;font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;max-height:300px;overflow:auto}.security-admin-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-kv{border:1px solid #30333a;border-radius:10px;background:#121418;padding:9px}.security-kv b{display:block;font-size:10px;color:#81858e;margin-bottom:3px}.security-kv span{font-size:12px;word-break:break-word}@media(max-width:900px){.security-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.specialized-section{padding-left:9px;padding-right:9px}.security-surface{padding:16px 12px 30px}.security-grid,.security-admin-grid{grid-template-columns:1fr}.security-head{align-items:center}.security-sub{max-width:75vw}}\n'
    '.who.workspace-who{height:27px;margin:0 0 5px 4px;display:flex;align-items:center;color:#dfe4ff}\n'
    '.workspace-message-mark{width:26px;height:26px;display:grid;place-items:center}\n'
    '.workspace-message-mark svg{width:23px;height:23px}\n'
    '.answerTools.compact-actions{display:flex;align-items:center;gap:2px;margin:8px 0 0 2px;position:relative}\n'
    '.answerTools.compact-actions .answerToolButton{width:34px;height:34px;padding:0;border:0;background:transparent;border-radius:9px;display:grid;place-items:center;color:#a9acb3;cursor:pointer}\n'
    '.answerTools.compact-actions .answerToolButton:hover,.answerTools.compact-actions .answerToolButton:focus-visible{background:#202226;color:#f1f2f4;outline:0}\n'
    '.answerTools.compact-actions .answerToolButton svg{width:20px;height:20px}\n'
    '.answerMoreWrap{position:relative;display:flex}\n'
    '.answerMoreMenu{position:absolute;left:0;bottom:38px;width:180px;padding:6px;background:#202125;border:1px solid #3a3c43;border-radius:12px;box-shadow:var(--shadow);z-index:12}\n'
    '.answerMoreMenu button{width:100%;height:36px;border:0;background:transparent;border-radius:8px;text-align:left;padding:0 10px;color:#e7e8eb;cursor:pointer;font-size:12px}\n'
    '.answerMoreMenu button:hover,.answerMoreMenu button:focus-visible{background:#2b2c31;outline:0}\n'
    '\n'
    '\n'
    '.security-config-layout{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(300px,.75fr);gap:12px}.security-config-panel{border:1px solid #30333a;background:#121418;border-radius:12px;padding:13px}.security-config-panel h3{font-size:13px;margin:0 0 10px}.security-config-help{color:#858a94;font-size:10px;line-height:1.45;margin:-4px 0 10px}.security-config-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-config-field{display:flex;flex-direction:column;gap:5px}.security-config-field.wide{grid-column:1/-1}.security-config-field label,.security-switch span{font-size:10px;color:#9398a2}.security-config-field input,.security-config-field select{width:100%;box-sizing:border-box;border:1px solid #363a42;background:#0e1013;color:#e7e9ed;border-radius:8px;padding:8px 9px;font-size:11px}.security-switch{display:flex;align-items:center;justify-content:space-between;gap:9px;border:1px solid #30343b;border-radius:9px;padding:8px 9px;background:#101216}.security-switch input{width:17px;height:17px}.security-policy-lock{border:1px solid #2e473d;background:#101c17;border-radius:10px;padding:10px;color:#b9d7c8;font-size:10px;line-height:1.55}.security-policy-warning{border-color:#5a4930;background:#211a10;color:#e3c895}.security-config-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.security-config-status{margin-top:10px;border:1px solid #30343b;border-radius:9px;padding:9px;font:10px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-word;min-height:38px;background:#0d0f12}.security-assets{display:flex;flex-direction:column;gap:8px}.security-asset-editor{border:1px solid #30343b;border-radius:10px;padding:10px;background:#0f1115}.security-asset-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}.security-asset-head b{font-size:11px}.security-cap-list{display:flex;gap:7px;flex-wrap:wrap;margin-top:3px}.security-cap-list label{display:flex;align-items:center;gap:4px;color:#b2b6bf;font-size:10px}.security-danger-note{font-size:10px;color:#e3c895;line-height:1.45;margin-top:7px}.security-config-meta{display:grid;gap:7px;margin-top:10px}.security-config-meta .security-kv{padding:8px}.security-config-footer-note{margin-top:11px;color:#777c86;font-size:10px;line-height:1.5}@media(max-width:980px){.security-config-layout{grid-template-columns:1fr}}@media(max-width:640px){.security-config-grid{grid-template-columns:1fr}.security-config-field.wide{grid-column:auto}}\n'
    '\n'
    '.security-soc-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.security-soc-section{margin-top:14px}.security-soc-section h3{font-size:13px;margin:0 0 8px}.security-soc-note{color:#858a94;font-size:10px;line-height:1.45;margin:0 0 8px}.security-truth-state{display:inline-block;border:1px solid #3c414a;border-radius:999px;padding:2px 7px;font-size:9px;font-weight:700;white-space:nowrap}.security-truth-state.verified{border-color:#315a46;color:#b8dbc9}.security-truth-state.inference{border-color:#5a4930;color:#e3c895}.security-truth-state.unknown{border-color:#454954;color:#b7bbc4}@media(max-width:900px){.security-soc-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:640px){.security-soc-grid{grid-template-columns:1fr}}\n'
    '\n'
    '.security-boundary-intro{border:1px solid #4b4232;background:#1b1710;border-radius:12px;padding:11px 12px;color:#ddc99f;font-size:11px;line-height:1.5;margin-bottom:12px}.security-boundary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-boundary-card{border:1px solid #343840;background:#111317;border-radius:11px;padding:11px}.security-boundary-card b{display:block;font-size:11px;margin-bottom:6px}.security-boundary-state{display:inline-block;border:1px solid #5a4930;border-radius:999px;padding:2px 7px;color:#e3c895;font-size:9px;font-weight:750;letter-spacing:.03em}.security-boundary-card p{margin:7px 0 0;color:#858a94;font-size:10px;line-height:1.45}@media(max-width:760px){.security-boundary-grid{grid-template-columns:1fr}}\n'
    '\n'
    '.workflow-library-toolbar{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin:-4px 0 12px;padding:9px;border:1px solid #33363c;border-radius:10px;background:#17181b}.workflow-library-toolbar input{min-width:220px;flex:1;background:#111216;color:var(--text);border:1px solid #3b3d43;border-radius:8px;padding:8px 9px}.workflow-library-current{font-size:10px;color:var(--muted);word-break:break-all}.workflow-library-drawer{margin:0 0 12px;border:1px solid #383b42;border-radius:12px;background:#121317;padding:11px}.workflow-library-filters{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-bottom:9px}.workflow-library-filters input{min-width:220px;flex:1;background:#0e0f12;color:var(--text);border:1px solid #35383f;border-radius:8px;padding:8px 9px}.workflow-library-filters select{background:#1b1d21;color:var(--text);border:1px solid #35383f;border-radius:8px;padding:8px 9px}.workflow-library-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}.workflow-library-item{border:1px solid #30333a;background:#17191d;border-radius:10px;padding:10px;cursor:pointer;text-align:left;color:var(--text)}.workflow-library-item:hover,.workflow-library-item:focus-visible{border-color:#555a66;outline:0}.workflow-library-item b{display:block;font-size:12px;margin-bottom:4px}.workflow-library-item span{display:block;font-size:10px;color:var(--muted);line-height:1.45}.workflow-library-item.archived{opacity:.68}.workflow-library-version-list{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.workflow-library-version{border:1px solid #353941;border-radius:999px;padding:4px 7px;font-size:9px;color:#b8bdc7}.workflow-library-authority{font-size:10px;color:#82c99a;margin-left:auto}@media(max-width:700px){.workflow-library-toolbar input,.workflow-library-filters input{min-width:100%;width:100%}.workflow-library-authority{width:100%;margin-left:0}}\n'
    '\n'
    '.security-confirmation-box{margin-top:10px;border:1px solid #5a4930;background:#211a10;border-radius:10px;padding:10px}.security-confirmation-box label{display:block;font-size:10px;color:#e3c895;margin-bottom:6px}.security-confirmation-box input{width:100%;box-sizing:border-box;border:1px solid #62533a;background:#0e1013;color:#f1e6cf;border-radius:8px;padding:8px 9px;font:10px ui-monospace,SFMono-Regular,Consolas,monospace}.security-confirmation-box small{display:block;color:#b9a27c;font-size:9px;line-height:1.45;margin-top:6px}.security-audit-list{display:flex;flex-direction:column;gap:6px;max-height:260px;overflow:auto}.security-audit-row{border:1px solid #30343b;border-radius:8px;background:#0e1013;padding:8px}.security-audit-row b{display:block;color:#c8ccd4;font-size:10px}.security-audit-row span{display:block;color:#818792;font-size:9px;line-height:1.45;margin-top:3px;word-break:break-word}.security-runtime-value{font:10px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}\n'
    '\n'
    '.security-asset-exact-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-left:auto}.security-asset-exact-state{font-size:9px;color:#8d929c;max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.security-asset-exact-state.ok{color:#9ecfb3}.security-asset-exact-state.warn{color:#e3c895}.security-asset-exact-state.error{color:#e0a4a4}\n'
    '\n'
    '.security-change-control{margin-top:10px;border:1px solid #3a414b;background:#0e1115;border-radius:10px;padding:10px}.security-change-control h4{margin:0 0 8px;font-size:11px}.security-change-control textarea{width:100%;min-height:64px;resize:vertical;box-sizing:border-box;border:1px solid #363a42;background:#0b0d10;color:#e7e9ed;border-radius:8px;padding:8px 9px;font-size:11px}.security-governance-state{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin:8px 0}.security-governance-state .security-kv{padding:8px}.security-history{margin-top:9px;max-height:220px;overflow:auto;display:flex;flex-direction:column;gap:6px}.security-history-row{border:1px solid #30343b;border-radius:8px;padding:8px;background:#0d0f12;font-size:10px;line-height:1.45}.security-history-row b{display:block;color:#d8dbe1}.security-rollback-row{display:flex;gap:7px;align-items:flex-end;margin-top:8px}.security-rollback-row .security-config-field{flex:1}@media(max-width:640px){.security-governance-state{grid-template-columns:1fr}.security-rollback-row{align-items:stretch;flex-direction:column}}\n'
    '</style>\n'
    '</head>\n'
    '<body>\n'
    '<div id="login">\n'
    '  <div class="login-card">\n'
    '    <h2>WorkSpace</h2>\n'
    '    <p>Sign in to your local WorkSpace account.</p>\n'
    '    <input id="username" type="text" autocomplete="username" placeholder="Username">\n'
    '    <input id="key" type="password" autocomplete="current-password" placeholder="Password">\n'
    '    <button class="soft-btn primary" id="loginBtn">Sign in</button>\n'
    '    <div class="login-divider hidden" id="externalLoginDivider"><span>or</span></div>\n'
    '    <div class="external-login-list" id="externalLoginList"></div>\n'
    '    <div class="external-login-note hidden" id="externalLoginNote">External providers verify identity only. WorkSpace data, projects and AI permissions remain local.</div>\n'
    '    <div id="loginErr" class="login-error"></div>\n'
    '  </div>\n'
    '</div>\n'
    '\n'
    '<aside class="sidebar" id="sidebar">\n'
    '  <div class="sidebar-top">\n'
    '    <div class="workspace-logo">\n'
    '      <span class="logo-mark" aria-hidden="true">\n'
    '        <svg viewBox="0 0 24 24"><path d="M12 2.8 19.2 7v10L12 21.2 4.8 17V7z"/><path d="m8.2 9.2 3.8-2.1 3.8 2.1v5.6L12 16.9l-3.8-2.1z"/><path d="M12 7.1v9.8"/></svg>\n'
    '      </span>\n'
    '      <span class="logo-text">WorkSpace</span>\n'
    '    </div>\n'
    '    <button id="sidebarToggle" class="sidebar-toggle" type="button" aria-label="Collapse sidebar">\n'
    '      <svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="M9 4v16"/></svg>\n'
    '    </button>\n'
    '  </div>\n'
    '\n'
    '  <nav class="side-nav">\n'
    '    <button class="side-action" id="newChatBtn" type="button">\n'
    '      <svg viewBox="0 0 24 24"><path d="M12 20H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7"/><path d="m15 5 4 4"/><path d="M13 11 19.5 4.5a1.4 1.4 0 0 1 2 2L15 13l-4 1z"/></svg>\n'
    '      <span>New chat</span>\n'
    '    </button>\n'
    '    <button class="side-action" id="historySearchBtn" type="button">\n'
    '      <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>\n'
    '      <span>Search chats</span>\n'
    '    </button>\n'
    '    <button class="side-action" id="archivedChatsBtn" type="button">\n'
    '      <svg viewBox="0 0 24 24"><path d="M4 7h16v13H4z"/><path d="M3 4h18v3H3zM9 11h6"/></svg>\n'
    '      <span>Archived chats</span>\n'
    '    </button>\n'
    '  </nav>\n'
    '\n'
    '\n'
    '  <section class="specialized-section" id="specializedSection">\n'
    '    <div class="specialized-heading">SPECIALIZED</div>\n'
    '    <button class="side-action security-specialized-btn" id="securityAnalystBtn" type="button" title="Security Analyst">\n'
    '      <svg viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5-3.2 8.5-8 10-4.8-1.5-8-5-8-10V6z"/><path d="M8 12h2l1.2-3 1.7 6 1.1-3H17"/></svg>\n'
    '      <span class="security-label">Security Analyst</span>\n'
    '      <span class="security-specialized-badge" id="securityAnalystBadge">—</span>\n'
    '    </button>\n'
    '  </section>\n'
    '\n'
    '  <div class="history-search hidden" id="historySearchBox">\n'
    '    <input id="historySearchInput" type="search" autocomplete="off" placeholder="Search history">\n'
    '    <button id="clearHistorySearch" type="button" aria-label="Clear search">\n'
    '      <svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>\n'
    '    </button>\n'
    '  </div>\n'
    '\n'
    '  <div class="history-scroll">\n'
    '    <section class="history-section" id="projectsSection">\n'
    '      <div class="history-heading projects-heading"><span>Projects</span><button class="project-add-btn" id="addProjectBtn" type="button" title="New project" aria-label="New project"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg></button></div>\n'
    '      <div id="projectsList"></div>\n'
    '    </section>\n'
    '    <section class="history-section" id="pinnedSection">\n'
    '      <div class="history-heading">Pinned</div>\n'
    '      <div id="pinnedList"></div>\n'
    '    </section>\n'
    '    <section class="history-section">\n'
    '      <div class="history-heading" id="historyHeading">Chats</div>\n'
    '      <div id="historyList"></div>\n'
    '    </section>\n'
    '  </div>\n'
    '\n'
    '  <div class="account-wrap">\n'
    '    <div class="account-menu" id="accountMenu">\n'
    '      <button type="button" id="manageUsersBtn" class="hidden">Manage users</button>\n'
    '      <button type="button" id="changePasswordBtn">Change password</button>\n'
    '      <button type="button" id="logoutBtn">Log out</button>\n'
    '    </div>\n'
    '    <button class="account-btn" id="accountBtn" type="button">\n'
    '      <span class="account-avatar" id="accountAvatar">W</span>\n'
    '      <span class="account-copy">\n'
    '        <span class="account-name" id="accountName">WorkSpace User</span>\n'
    '        <span class="account-sub" id="accountSub">Local LAN session</span>\n'
    '      </span>\n'
    '      <span class="account-more"><svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg></span>\n'
    '    </button>\n'
    '  </div>\n'
    '</aside>\n'
    '\n'
    '<div class="main-shell">\n'
    '  <header class="topbar">\n'
    '    <button class="mobile-menu" id="mobileMenuBtn" type="button" aria-label="Open sidebar">\n'
    '      <svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg>\n'
    '    </button>\n'
    '    <div class="conversation-name" id="conversationName">New chat</div>\n'
    '    <div class="top-spacer"></div>\n'
    '    <div class="security-badge">Local-first</div>\n'
    '  </header>\n'
    '\n'
    '  <section class="security-surface" id="securityAnalystSurface" aria-label="Security Analyst">\n'
    '    <div class="security-shell">\n'
    '      <div class="security-head">\n'
    '        <div class="security-head-copy">\n'
    '          <h2>Security Analyst</h2>\n'
    '          <div class="security-sub">Read-only local monitoring view. No remediation, packet capture, policy mutation or network command authority is exposed here.</div>\n'
    '          <div class="security-status-row">\n'
    '            <span class="security-status-chip" id="securityHealthChip">Health: —</span>\n'
    '            <span class="security-status-chip" id="securityHighCriticalChip">High/Critical: —</span>\n'
    '            <span class="security-status-chip" id="securityCoverageChip">Coverage: —</span>\n'
    '          </div>\n'
    '        </div>\n'
    '        <button class="soft-btn" id="securityAnalystClose" type="button">Close</button>\n'
    '      </div>\n'
    '      <div class="security-tabs" role="tablist">\n'
    '        <button class="security-tab active" data-security-tab="overview" type="button">Overview</button>\n'
    '        <button class="security-tab" data-security-tab="network" type="button">Network</button>\n'
    '        <button class="security-tab" data-security-tab="findings" type="button">Findings</button>\n'
    '        <button class="security-tab" data-security-tab="events" type="button">Events &amp; Logs</button>\n'
    '        <button class="security-tab" data-security-tab="assets" type="button">Assets</button>\n'
    '        <button class="security-tab" data-security-tab="reports" type="button">Reports</button>\n'
    '        <button class="security-tab" data-security-tab="soc" id="securitySocTab" type="button">SOC</button>\n'
    '        <button class="security-tab" data-security-tab="boundaries" id="securityBoundaryTab" type="button">Boundaries</button>\n'
    '        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>\n'
    '        <button class="security-tab" data-security-tab="admin" id="securityAdminTab" type="button">Administration</button>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view active" data-security-view="overview">\n'
    '        <div class="security-grid">\n'
    '          <div class="security-card"><div class="security-card-label">Health</div><div class="security-card-value" id="securityOverviewHealth">—</div></div>\n'
    '          <div class="security-card"><div class="security-card-label">High / Critical</div><div class="security-card-value" id="securityOverviewHighCritical">—</div></div>\n'
    '          <div class="security-card"><div class="security-card-label">Enabled assets</div><div class="security-card-value" id="securityOverviewAssets">—</div></div>\n'
    '          <div class="security-card"><div class="security-card-label">Latest coverage</div><div class="security-card-value" id="securityOverviewCoverage">—</div></div>\n'
    '        </div>\n'
    '        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th><th>Last seen</th></tr></thead><tbody id="securityOverviewFindings"></tbody></table></div>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view" data-security-view="network">\n'
    '        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Observed</th><th>Asset</th><th>Collector</th><th>Metric</th><th>Status</th><th>Value</th><th>Evidence</th></tr></thead><tbody id="securityNetworkRows"></tbody></table></div>\n'
    '        <div class="security-pager" id="securityNetworkPager"></div>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view" data-security-view="findings">\n'
    '        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th><th>Assets</th><th>Last seen</th></tr></thead><tbody id="securityFindingRows"></tbody></table></div>\n'
    '        <div class="security-pager" id="securityFindingPager"></div>\n'
    '        <pre class="security-detail" id="securityFindingDetail">Select a finding to inspect its bounded evidence references.</pre>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view" data-security-view="events">\n'
    '        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Observed</th><th>Source</th><th>Type</th><th>Severity</th><th>Category</th><th>Parser</th><th>Evidence</th></tr></thead><tbody id="securityEventRows"></tbody></table></div>\n'
    '        <div class="security-pager" id="securityEventPager"></div>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view" data-security-view="assets">\n'
    '        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Approved asset</th><th>Role</th><th>Enabled</th><th>Data class</th><th>Collectors</th><th>Observed state</th><th>Last observed</th></tr></thead><tbody id="securityAssetRows"></tbody></table></div>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view" data-security-view="reports">\n'
    '        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Archive</th><th>Period</th><th>Status</th><th>Attempt</th><th>Updated</th><th>Manifest</th></tr></thead><tbody id="securityReportRows"></tbody></table></div>\n'
    '        <div class="security-pager" id="securityReportPager"></div>\n'
    '      </div>\n'
    '\n'
    '\n'
    '\n'
    '      <div class="security-view" data-security-view="soc" id="securitySocView">\n'
    '        <div class="security-soc-grid">\n'
    '          <div class="security-card"><div class="security-card-label">Today high / critical</div><div class="security-card-value" id="securitySocTodayRisk">—</div></div>\n'
    '          <div class="security-card"><div class="security-card-label">7d high / critical</div><div class="security-card-value" id="securitySoc7dRisk">—</div></div>\n'
    '          <div class="security-card"><div class="security-card-label">30d high / critical</div><div class="security-card-value" id="securitySoc30dRisk">—</div></div>\n'
    '          <div class="security-card"><div class="security-card-label">Today data gaps</div><div class="security-card-value" id="securitySocDataGaps">—</div></div>\n'
    '        </div>\n'
    '\n'
    '        <section class="security-soc-section" aria-labelledby="securitySocFindingsTitle">\n'
    '          <h3 id="securitySocFindingsTitle">Findings</h3>\n'
    '          <div class="security-soc-note">Bounded deterministic findings from the canonical SOC projection.</div>\n'
    '          <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th><th>Last seen</th><th>Evidence</th></tr></thead><tbody id="securitySocFindingRows"></tbody></table></div>\n'
    '        </section>\n'
    '\n'
    '        <section class="security-soc-section" aria-labelledby="securitySocEvidenceTitle">\n'
    '          <h3 id="securitySocEvidenceTitle">Evidence</h3>\n'
    '          <div class="security-soc-note">Opaque evidence references only. Raw logs and private asset identity are outside this view.</div>\n'
    '          <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Evidence reference</th></tr></thead><tbody id="securitySocEvidenceRows"></tbody></table></div>\n'
    '        </section>\n'
    '\n'
    '        <section class="security-soc-section" aria-labelledby="securitySocAnalystTitle">\n'
    '          <h3 id="securitySocAnalystTitle">Analyst assessment</h3>\n'
    '          <div class="security-soc-note">Enterprise truth states are limited to VERIFIED FACT, INFERENCE and UNKNOWN.</div>\n'
    '          <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Truth state</th><th>Statement</th><th>Evidence</th></tr></thead><tbody id="securitySocAnalystRows"></tbody></table></div>\n'
    '        </section>\n'
    '      </div>\n'
    '\n'
    '\n'
    '      <div class="security-view" data-security-view="boundaries" id="securityBoundaryView">\n'
    '        <div class="security-boundary-intro"><strong>Not Implemented — Authority Boundaries</strong><br>These capabilities are intentionally absent from the Security Analyst runtime. Visibility and advisory analysis do not grant execution authority.</div>\n'
    '        <div class="security-boundary-grid">\n'
    '          <div class="security-boundary-card"><b>Autonomous network discovery</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No autonomous target discovery or inventory enrollment.</p></div>\n'
    '          <div class="security-boundary-card"><b>Autonomous active scan</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No port scan, vulnerability scan, or scope expansion initiated by the analyst.</p></div>\n'
    '          <div class="security-boundary-card"><b>Automatic firewall or block action</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No firewall mutation, host blocking, ACL change, or containment action.</p></div>\n'
    '          <div class="security-boundary-card"><b>AI-triggered packet capture</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>The analyst cannot start capture. Any bounded incident capture remains a separate explicit admin-approved runner workflow.</p></div>\n'
    '          <div class="security-boundary-card"><b>Shell or network command execution</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No shell, SSH, arbitrary command, or device configuration execution from the analyst surface.</p></div>\n'
    '          <div class="security-boundary-card"><b>Autonomous remediation</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>Findings and analyst assessments remain advisory; no automatic corrective action is authorized.</p></div>\n'
    '        </div>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view" data-security-view="configuration" id="securityConfigView">\n'
    '        <div class="security-config-layout">\n'
    '          <div>\n'
    '            <div class="security-config-panel">\n'
    '              <h3>Monitoring &amp; safety policy</h3>\n'
    '              <div class="security-config-help">Configuration is admin-only. Saving never starts collectors, scans, packet capture, remediation, or shell commands.</div>\n'
    '              <div class="security-config-grid">\n'
    '                <div class="security-switch"><span>Enable monitoring</span><input id="secCfgEnabled" type="checkbox"></div>\n'
    '                <div class="security-switch"><span>Allow approved real-network reads</span><input id="secCfgRealNetwork" type="checkbox"></div>\n'
    '                <div class="security-config-field"><label>Profile ID</label><input id="secCfgProfile" value="default" maxlength="128"></div>\n'
    '                <div class="security-config-field"><label>Max workers (1–4)</label><input id="secCfgWorkers" type="number" min="1" max="4" value="4"></div>\n'
    '                <div class="security-config-field"><label>Timeout seconds (0.1–5)</label><input id="secCfgTimeout" type="number" min="0.1" max="5" step="0.1" value="3"></div>\n'
    '                <div class="security-config-field"><label>Max retries (0–1)</label><input id="secCfgRetries" type="number" min="0" max="1" value="1"></div>\n'
    '                <div class="security-switch wide"><span>Allow active liveness (ICMP/TCP only, never throughput)</span><input id="secCfgActiveLiveness" type="checkbox"></div>\n'
    '              </div>\n'
    '              <div class="security-policy-lock" style="margin-top:9px">Locked safety boundary: approved_inventory_only · read_only · non_disruptive_v1 · counter_only bandwidth · passive_only packet analysis.</div>\n'
    '              <div class="security-config-field wide" style="margin-top:9px"><label>Allowed capabilities</label><div class="security-cap-list" id="secCfgCaps"><label><input type="checkbox" value="snmpv3_read" checked> SNMPv3 read</label><label><input type="checkbox" value="local_net_read" checked> Local telemetry read</label><label><input type="checkbox" value="icmp_echo"> ICMP liveness</label><label><input type="checkbox" value="tcp_connect"> TCP liveness</label></div></div>\n'
    '            </div>\n'
    '\n'
    '            <div class="security-config-panel" style="margin-top:12px">\n'
    '              <h3>Local data &amp; secret boundary</h3>\n'
    '              <div class="security-config-help">Only opaque secret references are stored in monitoring configuration. Passwords, SNMP communities, tokens, auth keys and private keys are rejected by the backend contract.</div>\n'
    '              <div class="security-config-grid">\n'
    '                <div class="security-config-field wide"><label>Monitoring database path</label><input id="secCfgDatabase" autocomplete="off"></div>\n'
    '                <div class="security-config-field wide"><label>Local secret directory</label><input id="secCfgSecretDir" autocomplete="off"></div>\n'
    '              </div>\n'
    '            </div>\n'
    '\n'
    '            <div class="security-config-panel" style="margin-top:12px">\n'
    '              <div class="security-asset-head"><div><h3 style="margin:0">Approved asset inventory</h3><div class="security-config-help" style="margin:3px 0 0">Collectors can target only assets and capabilities explicitly listed here.</div></div><button class="soft-btn" id="secCfgAddAsset" type="button">Add asset</button></div>\n'
    '              <div class="security-assets" id="secCfgAssets"></div>\n'
    '            </div>\n'
    '          </div>\n'
    '\n'
    '          <div>\n'
    '            <div class="security-config-panel">\n'
    '              <h3>Configuration gate</h3>\n'
    '              <div class="security-policy-lock">Fail-closed defaults: monitoring off, real network off, passive packet analysis, no autonomous remediation, no web PCAP execution.</div>\n'
    '\n'
    '              <div class="security-change-control" id="secGovernancePanel">\n'
    '                <h4>Enterprise change control</h4>\n'
    '                <div class="security-config-help">Every production change requires a reason and the current revision. Stale saves, audit tampering and out-of-band drift are blocked.</div>\n'
    '                <div class="security-governance-state" id="secGovernanceState"></div>\n'
    '                <div class="security-config-field wide"><label>Change reason (required)</label><textarea id="secCfgChangeReason" maxlength="1200" placeholder="Ticket / incident / approved reason for this change"></textarea></div>\n'
    '                <div class="security-config-actions">\n'
    '                  <button class="soft-btn" id="secCfgHistory" type="button">History</button>\n'
    '                  <button class="soft-btn" id="secCfgAdopt" type="button">Adopt existing</button>\n'
    '                </div>\n'
    '                <div class="security-rollback-row">\n'
    '                  <div class="security-config-field"><label>Rollback source revision</label><input id="secCfgRollbackRevision" type="number" min="1" step="1" placeholder="e.g. 3"></div>\n'
    '                  <button class="soft-btn" id="secCfgRollback" type="button">Rollback as new revision</button>\n'
    '                </div>\n'
    '                <div class="security-history" id="secCfgHistoryList"></div>\n'
    '              </div>\n'
    '              <div class="security-config-actions">\n'
    '                <button class="soft-btn" id="secCfgReload" type="button">Reload</button>\n'
    '                <button class="soft-btn" id="secCfgValidate" type="button">Validate</button>\n'
    '                <button class="soft-btn" id="secCfgReadiness" type="button">Readiness check</button>\n'
    '                <button class="soft-btn" id="secCfgSave" type="button">Save configuration</button>\n'
    '              </div>\n'
    '              <div class="security-config-status" id="secCfgStatus">Open Configuration to load the current policy.</div>\n'
    '\n'
    '              <div class="security-confirmation-box">\n'
    '                <label for="secCfgStrongConfirmation">Strong confirmation for real-network authority changes</label>\n'
    '                <input id="secCfgStrongConfirmation" autocomplete="off" spellcheck="false" placeholder="ENABLE_APPROVED_REAL_NETWORK_MONITORING">\n'
    '                <small>Required by the backend when enabling approved real-network reads, enabling active liveness, enabling monitoring while real-network reads are armed, or changing approved inventory/policy while real-network monitoring is enabled. Saving itself never runs a collector or network action.</small>\n'
    '              </div>\n'
    '              <div class="security-config-meta" id="secCfgMeta"></div>\n'
    '              <div class="security-config-footer-note">Readiness check verifies configuration, local paths and opaque credential references only. It does not probe the network or read secret values.</div>\n'
    '            </div>\n'
    '\n'
    '            <div class="security-config-panel" style="margin-top:12px">\n'
    '              <div class="security-asset-head"><div><h3 style="margin:0">Configuration audit</h3><div class="security-config-help" style="margin:3px 0 0">Metadata only. Management hosts, credential references and raw secret material are never written to this audit view.</div></div><button class="soft-btn" id="secCfgAuditReload" type="button">Reload</button></div>\n'
    '              <div class="security-kv"><b>Running source SHA</b><span class="security-runtime-value" id="secCfgRuntimeSha">—</span></div>\n'
    '              <div class="security-kv" style="margin-top:7px"><b>Gateway</b><span id="secCfgRuntimeGateway">—</span></div>\n'
    '              <div class="security-audit-list" id="secCfgAuditRows" style="margin-top:8px"><div class="security-empty">No audit data loaded.</div></div>\n'
    '            </div>\n'
    '            <div class="security-config-panel" style="margin-top:12px">\n'
    '              <h3>Recommended telemetry strategy</h3>\n'
    '              <div class="security-config-help">Prefer passive/read-only evidence first: device counters and approved local telemetry. Structured IDS/NSM events can feed the existing event pipeline without granting the AI direct network authority.</div>\n'
    '              <div class="security-kv"><b>Default collection</b><span>SNMPv3 read-only + local telemetry</span></div>\n'
    '              <div class="security-kv" style="margin-top:7px"><b>Packet analysis</b><span>Passive only; incident PCAP requires separate admin approval and dedicated runner</span></div>\n'
    '              <div class="security-kv" style="margin-top:7px"><b>Actions</b><span>Advisory only; no automatic firewall/block/remediation authority</span></div>\n'
    '            </div>\n'
    '          </div>\n'
    '        </div>\n'
    '      </div>\n'
    '\n'
    '      <div class="security-view" data-security-view="admin">\n'
    '        <div class="security-admin-grid" id="securityAdminGrid"></div>\n'
    '      </div>\n'
    '    </div>\n'
    '  </section>\n'
    '  <main id="messages">\n'
    '    <div class="empty-state" id="emptyState">\n'
    '      <div class="empty-inner">\n'
    '        <div class="empty-logo"><svg viewBox="0 0 24 24"><path d="M12 2.8 19.2 7v10L12 21.2 4.8 17V7z"/><path d="m8.2 9.2 3.8-2.1 3.8 2.1v5.6L12 16.9l-3.8-2.1z"/></svg></div>\n'
    '        <div class="empty-title">How can WorkSpace help?</div>\n'
    '        <div class="empty-sub">Your chat history stays in the local WorkSpace database.</div>\n'
    '      </div>\n'
    '    </div>\n'
    '  </main>\n'
    '</div>\n'
    '\n'
    '<div class="composer-wrap">\n'
    '  <div class="composer-area">\n'
    '    <div class="disclaimer">WorkSpace may make mistakes. Check important info.</div>\n'
    '    <div id="attachments" class="attachments"></div>\n'
    '    <div id="modePill" class="mode-pill"><span id="modeLabel"></span><button type="button" id="clearMode">×</button></div>\n'
    '\n'
    '    <div class="plus-menu" id="plusMenu">\n'
    '      <button class="menu-row" type="button" data-action="upload">\n'
    '        <span class="menu-icon white"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg></span>\n'
    '        <span><span class="menu-title">Add photos & files</span><span class="menu-sub">Secure local upload</span></span><span class="menu-state">Ready</span>\n'
    '      </button>\n'
    '      <button class="menu-row" type="button" data-action="library">\n'
    '        <span class="menu-icon blue"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 15 3-3 2 2 3-4 3 5"/></svg></span>\n'
    '        <span><span class="menu-title">Add from library</span><span class="menu-sub">Reuse your validated uploads</span></span><span class="menu-state">Ready</span>\n'
    '      </button>\n'
    '      <button class="menu-row" type="button" data-action="image_generation">\n'
    '        <span class="menu-icon purple"><svg viewBox="0 0 24 24"><path d="m12 3 1.2 3.5L17 8l-3.8 1.5L12 13l-1.2-3.5L7 8l3.8-1.5z"/><path d="m18 13 .8 2.2L21 16l-2.2.8L18 19l-.8-2.2L15 16l2.2-.8z"/></svg></span>\n'
    '        <span><span class="menu-title">Create image</span><span class="menu-sub">Local image model only</span></span><span class="menu-state">Not configured</span>\n'
    '      </button>\n'
    '      <button class="menu-row" type="button" data-action="web_search">\n'
    '        <span class="menu-icon blue"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4a13 13 0 0 1 0 16M12 4a13 13 0 0 0 0 16"/></svg></span>\n'
    '        <span><span class="menu-title">Web search</span><span class="menu-sub">Policy-authorized public research</span></span><span class="menu-state">Policy</span>\n'
    '      </button>\n'
    '      <button class="menu-row" type="button" data-action="deep_research">\n'
    '        <span class="menu-icon green"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4M8 11h6M11 8v6"/></svg></span>\n'
    '        <span><span class="menu-title">Deep research</span><span class="menu-sub">Thorough evidence-bounded workflow</span></span><span class="menu-state">Ready</span>\n'
    '      </button>\n'
    '      <button class="menu-row" type="button" data-action="github">\n'
    '        <span class="menu-icon white"><svg viewBox="0 0 24 24"><path d="M9 19c-4 1.2-4-2-5-2.5M14 22v-3.1c0-.9.1-1.5-.5-2.1 2.8-.3 5.7-1.4 5.7-6.2a4.9 4.9 0 0 0-1.3-3.4 4.6 4.6 0 0 0-.1-3.4S16.8 3.4 14 5a11.7 11.7 0 0 0-5 0C6.2 3.4 5.2 3.8 5.2 3.8a4.6 4.6 0 0 0-.1 3.4 4.9 4.9 0 0 0-1.3 3.4c0 4.8 2.9 5.9 5.7 6.2-.5.5-.6 1-.6 2.1V22"/></svg></span>\n'
    '        <span><span class="menu-title">GitHub</span><span class="menu-sub">Repository access</span></span><span class="menu-state">Operator only</span>\n'
    '      </button>\n'
    '\n'
    '      <button class="menu-row" type="button" data-action="figma" data-connect-action="true" role="menuitem">\n'
    '        <span class="menu-icon white">F</span>\n'
    '        <span><div class="menu-title">Figma</div><div class="menu-sub">Design-to-code workflows</div></span><span class="menu-state">Connect</span>\n'
    '      </button>\n'
    '      <button class="menu-row" type="button" data-action="canva" data-connect-action="true" role="menuitem">\n'
    '        <span class="menu-icon blue">C</span>\n'
    '        <span><div class="menu-title">Canva</div><div class="menu-sub">Create, review, and edit designs</div></span><span class="menu-state">Connect</span>\n'
    '      </button>\n'
    '      <button class="menu-row" type="button" data-action="gmail" data-connect-action="true" role="menuitem">\n'
    '        <span class="menu-icon white">M</span>\n'
    '        <span><div class="menu-title">Gmail</div><div class="menu-sub">Read and manage Gmail</div></span><span class="menu-state">Connect</span>\n'
    '      </button>\n'
    '      <div class="menu-divider"></div>\n'
    '      <div class="menu-options">\n'
    '        <select id="lang" hidden aria-hidden="true"><option value="auto" selected>Auto</option></select>\n'
    '        <label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + Slide PDF</option><option value="all">Report + PPTX + PDF</option></select></label>\n'
    '      </div>\n'
    '    </div>\n'
    '\n'
    '    <div class="composer">\n'
    '      <button class="circle-btn" id="plusBtn" type="button" aria-label="Open tools">\n'
    '        <svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>\n'
    '      </button>\n'
    '      <textarea id="input" placeholder="Ask WorkSpace" rows="1"></textarea>\n'
    '      <div class="composer-actions">\n'
    '        <select class="effort-select" id="effort" aria-label="Reasoning effort"><option value="standard">Standard</option><option value="high" selected>High</option></select>\n'
    '        <div class="vline"></div>\n'
    '        <button class="circle-btn" id="micBtn" type="button" aria-label="Voice input" aria-disabled="true">\n'
    '          <svg viewBox="0 0 24 24"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.5 11.5a6.5 6.5 0 0 0 13 0M12 18v3M9 21h6"/></svg>\n'
    '        </button>\n'
    '        <button class="circle-btn" id="sendBtn" type="button" aria-label="Send">\n'
    '          <svg viewBox="0 0 24 24"><path d="M12 19V5M6.5 10.5 12 5l5.5 5.5"/></svg>\n'
    '        </button>\n'
    '      </div>\n'
    '    </div>\n'
    '    <input id="fileInput" type="file" multiple hidden accept=".txt,.md,.markdown,.html,.htm,.pdf,.docx,.pptx,.xlsx,.csv,.tsv,.json,.jsonl,.xml,.yaml,.yml,.log,.ini,.cfg,.conf,.zip,.png,.jpg,.jpeg,.webp,text/plain,text/markdown,text/html,text/csv,application/pdf,application/json,application/xml,application/zip,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,image/png,image/jpeg,image/webp">\n'
    '  </div>\n'
    '</div>\n'
    '\n'
    '\n'
    '<div class="library-modal" id="userAdminModal">\n'
    '  <div class="library-card user-admin-card">\n'
    '    <div class="library-head"><h2>WorkSpace users</h2><button class="soft-btn" id="closeUserAdmin" type="button">Close</button></div>\n'
    '    <form class="user-admin-form" id="createUserForm">\n'
    '      <input id="newUsername" autocomplete="off" placeholder="Username" required>\n'
    '      <input id="newDisplayName" autocomplete="off" placeholder="Display name" required>\n'
    '      <input id="newDepartment" autocomplete="off" placeholder="Department">\n'
    '      <input id="newTitle" autocomplete="off" placeholder="Job title">\n'
    '      <select id="newRole"><option value="user">User</option><option value="admin">Admin</option></select>\n'
    '      <input id="newUserPassword" type="password" autocomplete="new-password" placeholder="Temporary password (16+ chars)" required>\n'
    '      <button class="soft-btn primary wide" type="submit">Create account</button>\n'
    '    </form>\n'
    '    <div class="user-admin-users" id="userAdminUsers"></div>\n'
    '    <div class="external-admin" id="externalIdentityAdmin">\n'
    '      <h3>External login identities</h3>\n'
    '      <div class="external-status">Google, GitHub and LINE identities must be explicitly bound to an existing local WorkSpace user.</div>\n'
    '      <div id="externalIdentityList"></div>\n'
    '    </div>\n'
    '  </div>\n'
    '</div>\n'
    '<div class="library-modal" id="passwordModal">\n'
    '  <div class="library-card" style="width:min(460px,96vw)">\n'
    '    <div class="library-head"><h2>Change password</h2><button class="soft-btn" id="closePasswordModal" type="button">Close</button></div>\n'
    '    <form class="password-form" id="passwordForm">\n'
    '      <input id="currentPassword" type="password" autocomplete="current-password" placeholder="Current password" required>\n'
    '      <input id="newPassword" type="password" autocomplete="new-password" placeholder="New password (16+ chars)" required>\n'
    '      <input id="confirmPassword" type="password" autocomplete="new-password" placeholder="Confirm new password" required>\n'
    '      <button class="soft-btn primary" type="submit">Change password</button>\n'
    '    </form>\n'
    '  </div>\n'
    '</div>\n'
    '\n'
    '<div class="conversation-menu" id="conversationMenu">\n'
    '  <button type="button" id="conversationRenameAction">Rename</button>\n'
    '  <button type="button" id="conversationPinAction">Pin</button>\n'
    '  <button type="button" id="conversationMoveAction">Move to project</button>\n'
    '  <button type="button" id="conversationArchiveAction">Archive</button>\n'
    '  <button type="button" class="danger" id="conversationDeleteAction">Delete</button>\n'
    '</div>\n'
    '<div class="library-modal" id="renameConversationModal">\n'
    '  <div class="library-card conversation-dialog">\n'
    '    <div class="library-head"><h2>Rename chat</h2><button class="soft-btn" id="closeRenameConversation" type="button">Close</button></div>\n'
    '    <form class="conversation-dialog-body" id="renameConversationForm">\n'
    '      <input id="renameConversationInput" autocomplete="off" maxlength="96" placeholder="Conversation title" required>\n'
    '      <div class="dialog-actions"><button class="soft-btn" id="cancelRenameConversation" type="button">Cancel</button><button class="soft-btn primary" type="submit">Save</button></div>\n'
    '    </form>\n'
    '  </div>\n'
    '</div>\n'
    '<div class="library-modal" id="deleteConversationModal">\n'
    '  <div class="library-card conversation-dialog">\n'
    '    <div class="library-head"><h2>Delete chat?</h2><button class="soft-btn" id="closeDeleteConversation" type="button">Close</button></div>\n'
    '    <div class="conversation-dialog-body">\n'
    '      <p class="conversation-dialog-copy" id="deleteConversationCopy">This permanently deletes the selected conversation and its saved messages.</p>\n'
    '      <div class="dialog-actions"><button class="soft-btn" id="cancelDeleteConversation" type="button">Cancel</button><button class="soft-btn danger" id="confirmDeleteConversation" type="button">Delete</button></div>\n'
    '    </div>\n'
    '  </div>\n'
    '</div>\n'
    '\n'
    '<div class="project-menu" id="projectMenu">\n'
    '  <button type="button" id="projectRenameAction">Rename project</button>\n'
    '  <button type="button" class="danger" id="projectDeleteAction">Delete project</button>\n'
    '</div>\n'
    '<div class="library-modal" id="projectEditModal">\n'
    '  <div class="library-card conversation-dialog">\n'
    '    <div class="library-head"><h2 id="projectEditTitle">New project</h2><button class="soft-btn" id="closeProjectEdit" type="button">Close</button></div>\n'
    '    <form class="conversation-dialog-body" id="projectEditForm">\n'
    '      <input id="projectNameInput" autocomplete="off" maxlength="64" placeholder="Project name" required>\n'
    '      <div class="dialog-actions"><button class="soft-btn" id="cancelProjectEdit" type="button">Cancel</button><button class="soft-btn primary" type="submit">Save</button></div>\n'
    '    </form>\n'
    '  </div>\n'
    '</div>\n'
    '<div class="library-modal" id="projectDeleteModal">\n'
    '  <div class="library-card conversation-dialog">\n'
    '    <div class="library-head"><h2>Delete project?</h2><button class="soft-btn" id="closeProjectDelete" type="button">Close</button></div>\n'
    '    <div class="conversation-dialog-body">\n'
    '      <p class="conversation-dialog-copy" id="projectDeleteCopy">Chats are kept and moved back to the main chat list.</p>\n'
    '      <div class="dialog-actions"><button class="soft-btn" id="cancelProjectDelete" type="button">Cancel</button><button class="soft-btn danger" id="confirmProjectDelete" type="button">Delete project</button></div>\n'
    '    </div>\n'
    '  </div>\n'
    '</div>\n'
    '<div class="library-modal" id="moveProjectModal">\n'
    '  <div class="library-card conversation-dialog">\n'
    '    <div class="library-head"><h2>Move chat to project</h2><button class="soft-btn" id="closeMoveProject" type="button">Close</button></div>\n'
    '    <div class="move-project-list" id="moveProjectList"></div>\n'
    '  </div>\n'
    '</div>\n'
    '<div class="library-modal" id="libraryModal">\n'
    '  <div class="library-card">\n'
    '    <div class="library-head"><h2>Your WorkSpace library</h2><button class="soft-btn" id="closeLibrary" type="button">Close</button></div>\n'
    '    <div class="library-list" id="libraryList"></div>\n'
    '    <div class="library-foot"><button class="soft-btn" id="libraryCancel" type="button">Cancel</button><button class="soft-btn primary" id="libraryAdd" type="button">Add selected</button></div>\n'
    '  </div>\n'
    '</div>\n'
    '<div class="toast" id="toast"></div>\n'
    '\n'
    '<script>\n'
    "const messages=document.getElementById('messages'),input=document.getElementById('input');\n"
    'const state={\n'
    "  capabilities:null,selectedFiles:[],selectedLibrary:new Map(),requestMode:'chat',\n"
    "  currentConversationId:null,conversations:[],searchQuery:'',searchTimer:null,\n"
    "  session:null,sidebarCollapsed:localStorage.getItem('workspace.sidebarCollapsed')==='1'\n"
    '};\n'
    'function svgChat(){return \'<svg viewBox="0 0 24 24"><path d="M20 15a4 4 0 0 1-4 4H8l-4 2 1.2-4.2A7 7 0 0 1 4 13V9a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4z"/></svg>\'}\n'
    "function showToast(text){const e=document.getElementById('toast');e.textContent=text;e.classList.add('show');clearTimeout(showToast.t);showToast.t=setTimeout(()=>e.classList.remove('show'),2500)}\n"
    "function hideEmpty(){const e=document.getElementById('emptyState');if(e)e.remove()}\n"
    'function showEmpty(){messages.innerHTML=\'<div class="empty-state" id="emptyState"><div class="empty-inner"><div class="empty-logo"><svg viewBox="0 0 24 24"><path d="M12 2.8 19.2 7v10L12 21.2 4.8 17V7z"/><path d="m8.2 9.2 3.8-2.1 3.8 2.1v5.6L12 16.9l-3.8-2.1z"/></svg></div><div class="empty-title">How can WorkSpace help?</div><div class="empty-sub">Your chat history stays in the local WorkSpace database.</div></div></div>\'}\n'
    "async function api(url,opt={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(opt.headers||{})},...opt});let data={};try{data=await r.json()}catch(e){}if(r.status===401){document.getElementById('login').classList.remove('hidden');throw new Error('Authentication required')}if(!r.ok)throw new Error(data.error||r.statusText);return data}\n"
    '\n'
    "function applySidebarState(){const side=document.getElementById('sidebar');side.classList.toggle('collapsed',state.sidebarCollapsed);document.body.classList.toggle('sidebar-collapsed',state.sidebarCollapsed);document.getElementById('sidebarToggle').setAttribute('aria-label',state.sidebarCollapsed?'Expand sidebar':'Collapse sidebar')}\n"
    "function setSidebarCollapsed(value){state.sidebarCollapsed=!!value;localStorage.setItem('workspace.sidebarCollapsed',state.sidebarCollapsed?'1':'0');applySidebarState()}\n"
    'function toggleSidebar(){setSidebarCollapsed(!state.sidebarCollapsed)}\n'
    '\n'
    "function appendInline(el,text){const re=/(https?:\\/\\/[^\\s]+)/g;let pos=0;for(const m of String(text||'').matchAll(re)){el.appendChild(document.createTextNode(text.slice(pos,m.index)));const a=document.createElement('a');a.href=m[0];a.target='_blank';a.rel='noopener noreferrer';a.textContent=m[0];a.style.color='var(--accent)';el.appendChild(a);pos=m.index+m[0].length}el.appendChild(document.createTextNode(String(text||'').slice(pos)))}\n"
    "function renderReport(text){const root=document.createElement('div');root.className='report';let list=null;for(const raw of String(text||'').split('\\n')){const line=raw.trimEnd();if(!line.trim()){list=null;continue}if(line==='---'){root.appendChild(document.createElement('hr'));list=null;continue}const h=line.match(/^(#{1,2})\\s+(.*)$/);if(h){const el=document.createElement(h[1].length===1?'h1':'h2');appendInline(el,h[2].replace(/\\*\\*/g,''));root.appendChild(el);list=null;continue}if(line.startsWith('> ')){const q=document.createElement('blockquote');appendInline(q,line.slice(2).replace(/\\*\\*/g,''));root.appendChild(q);list=null;continue}if(line.startsWith('- ')){if(!list){list=document.createElement('ul');root.appendChild(list)}const li=document.createElement('li');appendInline(li,line.slice(2).replace(/\\*\\*/g,''));list.appendChild(li);continue}const p=document.createElement('p');appendInline(p,line.replace(/\\*\\*/g,'').replace(/`/g,''));root.appendChild(p);list=null}return root}\n"
    "function renderStages(stages){const wrap=document.createElement('div');wrap.className='stages';for(const s of stages||[]){const e=document.createElement('div');e.className='stage '+s.status;const b=document.createElement('b'),small=document.createElement('small');b.textContent=s.label+' · '+s.status;small.textContent=s.detail||'';e.append(b,small);wrap.appendChild(e)}return wrap}\n"
    'function isPrimary(a){return /_report\\.(docx|pdf|md)$/i.test(a.name)||/\\.pptx$/i.test(a.name)}\n'
    "function renderArtifacts(items){const wrap=document.createElement('div'),primary=document.createElement('div'),tech=document.createElement('details');primary.className='downloads';tech.className='tech';const sum=document.createElement('summary');sum.textContent='Technical evidence / 監査用データ';tech.appendChild(sum);let count=0;for(const a of items||[]){const x=document.createElement('a');x.href=a.url;x.textContent='↓ '+a.name;if(isPrimary(a)){if(/_report\\.(docx|pdf)$/i.test(a.name))x.className='primaryFile';primary.appendChild(x)}else{tech.appendChild(x);count++}}if(primary.children.length)wrap.appendChild(primary);if(count)wrap.appendChild(tech);return wrap}\n"
    "async function copyAnswer(node){const text=node.dataset.answer||'';try{await navigator.clipboard.writeText(text)}catch(e){const t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}showToast('Copied')}\n"
    'function workspaceSenderMark(){const h=document.createElement(\'div\');h.className=\'who workspace-who\';h.title=\'WorkSpace\';h.setAttribute(\'aria-label\',\'WorkSpace\');h.innerHTML=\'<span class="workspace-message-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 2.8 19.2 7v10L12 21.2 4.8 17V7z"/><path d="m8.2 9.2 3.8-2.1 3.8 2.1v5.6L12 16.9l-3.8-2.1z"/></svg></span>\';return h}\n'
    "function shouldShowAnswerStages(job,route){if(!job||!job.stages||!job.stages.length)return false;const exceptional=job.stages.some(s=>['failed','blocked','waiting_human','waiting-human'].includes(String(s.status||'').toLowerCase()));if(exceptional)return true;const status=String(job.status||'').toLowerCase();if(['failed','blocked','waiting_human','waiting-human'].includes(status))return true;if(job.answer)return false;return route!=='direct_chat'}\n"
    "function answerToolButton(label,icon,handler){const b=document.createElement('button');b.type='button';b.className='answerToolButton';b.title=label;b.setAttribute('aria-label',label);b.innerHTML=icon;b.onclick=handler;return b}\n"
    "function exportAnswer(node){const text=node.dataset.answer||'';if(!text)return;const blob=new Blob([text],{type:'text/plain;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='workspace-answer-'+new Date().toISOString().slice(0,10)+'.txt';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),0);showToast('Exported locally')}\n"
    "function previousUserPrompt(node){let prev=node.previousElementSibling;while(prev){if(prev.classList&&prev.classList.contains('user'))return prev.dataset.answer||'';prev=prev.previousElementSibling}return ''}\n"
    "async function regenerateAnswer(node){if(document.getElementById('sendBtn').disabled){showToast('WorkSpace is already working');return}const prompt=previousUserPrompt(node);if(!prompt){showToast('Original prompt unavailable');return}const marker='\\n\\nAttached:';const at=prompt.indexOf(marker);input.value=at>=0?prompt.slice(0,at):prompt;input.dispatchEvent(new Event('input',{bubbles:true}));input.focus();if(at>=0){showToast('Reattach files before regenerating');return}await sendMsg()}\n"
    "function answerMoreItem(label,handler){const b=document.createElement('button');b.type='button';b.textContent=label;b.onclick=handler;return b}\n"
    'function renderActions(node,job){const answer=(job&&job.answer)||node.dataset.answer||\'\';if(!answer)return;const bar=document.createElement(\'div\');bar.className=\'answerTools compact-actions\';const copyIcon=\'<svg viewBox="0 0 24 24"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>\';const exportIcon=\'<svg viewBox="0 0 24 24"><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M5 14v5h14v-5"/></svg>\';const retryIcon=\'<svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 1 0 1 4"/><path d="M20 4v7h-7"/></svg>\';const moreIcon=\'<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.6" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1.6" fill="currentColor" stroke="none"/></svg>\';bar.appendChild(answerToolButton(\'Copy answer\',copyIcon,()=>copyAnswer(node)));bar.appendChild(answerToolButton(\'Export answer\',exportIcon,()=>exportAnswer(node)));bar.appendChild(answerToolButton(\'Regenerate answer\',retryIcon,()=>regenerateAnswer(node)));const wrap=document.createElement(\'span\');wrap.className=\'answerMoreWrap\';const menu=document.createElement(\'div\');menu.className=\'answerMoreMenu\';menu.hidden=true;menu.appendChild(answerMoreItem(\'Copy answer\',()=>{menu.hidden=true;copyAnswer(node)}));menu.appendChild(answerMoreItem(\'Export .txt\',()=>{menu.hidden=true;exportAnswer(node)}));menu.appendChild(answerMoreItem(\'Regenerate\',()=>{menu.hidden=true;regenerateAnswer(node)}));const more=answerToolButton(\'More answer actions\',moreIcon,()=>{menu.hidden=!menu.hidden});more.setAttribute(\'aria-haspopup\',\'menu\');wrap.append(more,menu);bar.appendChild(wrap);node.appendChild(bar)}\n'
    "function addMessage(who,text,cls='',job=null){hideEmpty();const d=document.createElement('div');d.className='msg '+cls;d.dataset.uiRoute=job&&job.ui_route?job.ui_route:'';let h;if(cls.includes('user')){h=document.createElement('div');h.className='who';h.textContent=who}else h=workspaceSenderMark();d.appendChild(h);if(shouldShowAnswerStages(job,d.dataset.uiRoute))d.appendChild(renderStages(job.stages));const b=document.createElement('div');b.className='bubble';if(cls.includes('user'))b.textContent=text;else b.appendChild(renderReport(text));d.appendChild(b);d.dataset.answer=job&&job.answer?job.answer:text;if(!cls.includes('user')&&d.dataset.answer)renderActions(d,job||{answer:d.dataset.answer});if(job&&job.artifacts&&job.artifacts.length)d.appendChild(renderArtifacts(job.artifacts));messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}\n"
    "function updateNode(node,j){if(j.ui_route)node.dataset.uiRoute=j.ui_route;const old=node.querySelector('.stages');if(old)old.remove();if(shouldShowAnswerStages(j,node.dataset.uiRoute))node.insertBefore(renderStages(j.stages),node.querySelector('.bubble'));const text=(j.status==='queued'||j.status==='running')?'WorkSpace is working…':(j.answer||(j.error||j.status));const b=node.querySelector('.bubble');b.innerHTML='';b.appendChild(renderReport(text));node.dataset.answer=j.answer||'';for(const e of Array.from(node.querySelectorAll('.answerTools,.downloads,.tech')))e.remove();if(j.answer)renderActions(node,j);if(j.artifacts&&j.artifacts.length)node.appendChild(renderArtifacts(j.artifacts));node.classList.toggle('error',j.status==='failed'&&!j.answer)}\n"
    '\n'
    'function renderHistoryList(){const pinned=document.getElementById(\'pinnedList\'),history=document.getElementById(\'historyList\');pinned.innerHTML=\'\';history.innerHTML=\'\';const p=state.conversations.filter(x=>x.pinned),normal=state.conversations.filter(x=>!x.pinned);document.getElementById(\'pinnedSection\').classList.toggle(\'hidden\',p.length===0);document.getElementById(\'historyHeading\').textContent=state.searchQuery?\'Search results\':\'Chats\';const build=(item)=>{const row=document.createElement(\'div\');row.className=\'conversation-row\'+(item.conversation_id===state.currentConversationId?\' active\':\'\');row.dataset.id=item.conversation_id;const icon=document.createElement(\'span\');icon.className=\'conversation-icon\';icon.innerHTML=svgChat();const title=document.createElement(\'span\');title.className=\'conversation-title\';title.textContent=item.title;title.title=item.title;const pin=document.createElement(\'button\');pin.type=\'button\';pin.className=\'pin-btn\'+(item.pinned?\' pinned\':\'\');pin.title=item.pinned?\'Unpin\':\'Pin\';pin.setAttribute(\'aria-label\',pin.title);pin.innerHTML=\'<svg viewBox="0 0 24 24"><path d="m9 3 6 0 1 5 3 3-6 1v7l-1 2-1-2v-7l-6-1 3-3z"/></svg>\';pin.onclick=(e)=>{e.stopPropagation();setPinned(item.conversation_id,!item.pinned)};row.append(icon,title,pin);row.onclick=()=>openConversation(item.conversation_id);return row};for(const item of p)pinned.appendChild(build(item));for(const item of normal)history.appendChild(build(item));if(!p.length&&!normal.length){const e=document.createElement(\'div\');e.className=\'history-empty\';e.textContent=state.searchQuery?\'No matching chats\':\'No saved chats yet\';history.appendChild(e)}}\n'
    "async function loadConversations(query=state.searchQuery){state.searchQuery=String(query||'').trim();const d=await api('/api/conversations'+(state.searchQuery?'?q='+encodeURIComponent(state.searchQuery):''));state.conversations=d.conversations||[];renderHistoryList()}\n"
    "async function openConversation(id){const d=await api('/api/conversations/'+encodeURIComponent(id));state.currentConversationId=d.conversation_id;localStorage.setItem('workspace.currentConversationId',d.conversation_id);document.getElementById('conversationName').textContent=d.title||'Chat';messages.innerHTML='';for(const m of d.messages||[]){if(m.role==='user')addMessage('You',m.content,'user');else addMessage('WorkSpace',m.content,m.status==='failed'?'error':'')}if(!(d.messages||[]).length)showEmpty();renderHistoryList();if(window.innerWidth<=760)setSidebarCollapsed(true)}\n"
    "function newChat(){state.currentConversationId=null;localStorage.removeItem('workspace.currentConversationId');document.getElementById('conversationName').textContent='New chat';messages.innerHTML='';showEmpty();renderHistoryList();input.focus();if(window.innerWidth<=760)setSidebarCollapsed(true)}\n"
    "async function setPinned(id,pinned){try{await api('/api/conversations/'+encodeURIComponent(id)+'/pin',{method:'POST',body:JSON.stringify({pinned:!!pinned})});await loadConversations()}catch(e){showToast(e.message)}}\n"
    "function openSearch(){if(state.sidebarCollapsed)setSidebarCollapsed(false);const box=document.getElementById('historySearchBox');box.classList.remove('hidden');setTimeout(()=>document.getElementById('historySearchInput').focus(),40)}\n"
    "function closeSearch(){state.searchQuery='';const inputEl=document.getElementById('historySearchInput');inputEl.value='';document.getElementById('historySearchBox').classList.add('hidden');loadConversations('').catch(()=>{})}\n"
    '\n'
    "function cap(name){return state.capabilities&&state.capabilities.features&&state.capabilities.features[name]?state.capabilities.features[name]:{enabled:false,state_label:'Unavailable',reason:'Capability unavailable'}}\n"
    "function syncCapabilities(){for(const row of document.querySelectorAll('.menu-row[data-action]')){const name=row.dataset.action,feature=name==='upload'?cap('upload'):name==='library'?cap('library'):cap(name);row.classList.toggle('disabled',!feature.enabled);row.setAttribute('aria-disabled',feature.enabled?'false':'true');const label=row.querySelector('.menu-state');if(label)label.textContent=feature.state_label||''}const mic=cap('voice_input');document.getElementById('micBtn').setAttribute('aria-disabled',mic.enabled?'false':'true')}\n"
    "async function loadCapabilities(){state.capabilities=await api('/api/capabilities');syncCapabilities()}\n"
    "async function loadSession(){const d=await api('/api/session');state.session=d;document.getElementById('accountName').textContent=d.display_name||d.username||'WorkSpace User';document.getElementById('accountSub').textContent=d.subtitle||d.department||'WorkSpace user';document.getElementById('accountAvatar').textContent=d.initials||'W';document.getElementById('manageUsersBtn').classList.toggle('hidden',d.role!=='admin')}\n"
    "function setMode(mode){if(mode!=='chat'){const f=cap(mode);if(!f.enabled){showToast(f.reason||'This capability is unavailable');return}}state.requestMode=mode;const pill=document.getElementById('modePill'),label=document.getElementById('modeLabel');if(mode==='chat'){pill.classList.remove('visible');label.textContent=''}else{label.textContent=mode==='web_search'?'Web search':'Deep research';pill.classList.add('visible')}document.getElementById('plusMenu').classList.remove('open')}\n"
    "function renderAttachments(){const wrap=document.getElementById('attachments');wrap.innerHTML='';for(let i=0;i<state.selectedFiles.length;i++){const f=state.selectedFiles[i],c=document.createElement('div');c.className='chip';const s=document.createElement('span');s.textContent=f.name;const b=document.createElement('button');b.type='button';b.textContent='×';b.onclick=()=>{state.selectedFiles.splice(i,1);renderAttachments()};c.append(s,b);wrap.appendChild(c)}for(const [id,item] of state.selectedLibrary){const c=document.createElement('div');c.className='chip';const s=document.createElement('span');s.textContent=item.name;const b=document.createElement('button');b.type='button';b.textContent='×';b.onclick=()=>{state.selectedLibrary.delete(id);renderAttachments()};c.append(s,b);wrap.appendChild(c)}}\n"
    "function fileBase64(file){return new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>{const v=String(r.result||'');resolve(v.includes(',')?v.split(',',2)[1]:v)};r.onerror=()=>reject(r.error||new Error('File read failed'));r.readAsDataURL(file)})}\n"
    "async function uploadOne(file){const max=state.capabilities?.limits?.max_upload_bytes||16*1024*1024;if(file.size>max)throw new Error(file.name+': file exceeds '+Math.ceil(max/1024/1024)+' MiB');const data=await fileBase64(file);return api('/api/upload',{method:'POST',body:JSON.stringify({name:file.name,type:file.type||'',data_base64:data})})}\n"
    "async function openLibrary(){if(!cap('library').enabled){showToast(cap('library').reason);return}const d=await api('/api/uploads'),list=document.getElementById('libraryList');list.innerHTML='';if(!(d.uploads||[]).length){const e=document.createElement('div');e.className='library-empty';e.textContent='No validated uploads for this LAN session yet.';list.appendChild(e)}for(const item of d.uploads||[]){const row=document.createElement('label');row.className='library-item';const ck=document.createElement('input');ck.type='checkbox';ck.dataset.id=item.upload_id;ck.checked=state.selectedLibrary.has(item.upload_id);const body=document.createElement('div'),name=document.createElement('div'),meta=document.createElement('div');name.className='library-name';name.textContent=item.name;meta.className='library-meta';meta.textContent=item.kind+' · '+Math.ceil(item.size/1024)+' KB';body.append(name,meta);const stateEl=document.createElement('span');stateEl.className='menu-state';stateEl.textContent=item.document_count+' docs · '+item.image_count+' images';row.append(ck,body,stateEl);row.dataset.payload=JSON.stringify(item);list.appendChild(row)}document.getElementById('libraryModal').classList.add('open');document.getElementById('plusMenu').classList.remove('open')}\n"
    "function applyLibrary(){for(const row of document.querySelectorAll('.library-item')){const ck=row.querySelector('input');if(!ck)continue;const item=JSON.parse(row.dataset.payload);if(ck.checked)state.selectedLibrary.set(item.upload_id,item);else state.selectedLibrary.delete(item.upload_id)}renderAttachments();document.getElementById('libraryModal').classList.remove('open')}\n"
    "function unavailable(name){const f=cap(name);showToast(f.reason||'This feature is not available')}\n"
    '\n'
    "function uploadProcessingLabel(file,result,index,total){const docs=Number(result&&result.document_count||0),images=Number(result&&result.image_count||0),warnings=Array.isArray(result&&result.warnings)?result.warnings.length:0;const semantic=docs>0?(docs+' document'+(docs===1?'':'s')+' parsed'):(images>0?'image stored · vision unavailable':'validated');return 'Processed '+index+'/'+total+': '+file.name+' · '+semantic+(warnings?' · '+warnings+' warning'+(warnings===1?'':'s'):'')}\n"
    "async function sendMsg(){const text=input.value.trim();if(!text)return;document.getElementById('sendBtn').disabled=true;const files=state.selectedFiles.slice(),libraryIds=Array.from(state.selectedLibrary.keys()),names=[...files.map(f=>f.name),...Array.from(state.selectedLibrary.values()).map(x=>x.name)];input.value='';state.selectedFiles=[];state.selectedLibrary.clear();renderAttachments();addMessage('You',text+(names.length?'\\n\\nAttached: '+names.join(', '):''),'user');const directUi=state.requestMode==='chat'&&document.getElementById('fmt').value==='source';const pending=addMessage('WorkSpace',files.length?'Uploading and processing files locally…':(libraryIds.length?'Preparing attached library files…':'Queued…'),'',{answer:'',ui_route:directUi?'direct_chat':'workflow',stages:directUi?[]:[{label:'Research',status:'queued'},{label:'Presentation',status:'queued'},{label:'Human Report',status:'queued'}],artifacts:[]});try{const uploadIds=libraryIds.slice();for(let i=0;i<files.length;i++){pending.querySelector('.bubble').textContent='Uploading '+(i+1)+'/'+files.length+': '+files[i].name;const result=await uploadOne(files[i]);uploadIds.push(result.upload_id);pending.querySelector('.bubble').textContent=uploadProcessingLabel(files[i],result,i+1,files.length)}if(uploadIds.length)pending.querySelector('.bubble').textContent='Attachments processed locally. Retrieving relevant content for this request…';const d=await api('/api/chat',{method:'POST',body:JSON.stringify({message:text,language:document.getElementById('lang').value,format:document.getElementById('fmt').value,upload_ids:uploadIds,mode:state.requestMode,effort:document.getElementById('effort').value,conversation_id:state.currentConversationId})});state.currentConversationId=d.conversation_id;localStorage.setItem('workspace.currentConversationId',d.conversation_id);document.getElementById('conversationName').textContent=text.replace(/\\s+/g,' ').slice(0,96);updateNode(pending,d);await loadConversations();poll(d.job_id,pending,d.conversation_id)}catch(e){pending.querySelector('.bubble').textContent=e.message;pending.classList.add('error')}finally{document.getElementById('sendBtn').disabled=false}}\n"
    "async function poll(id,node,conversationId){try{const j=await api('/api/jobs/'+id);if(j.status==='queued'||j.status==='running'){if(node.isConnected)updateNode(node,j);setTimeout(()=>poll(id,node,conversationId),1800);return}if(node.isConnected)updateNode(node,j);await loadConversations();if(state.currentConversationId===conversationId&&!node.isConnected)await openConversation(conversationId)}catch(e){if(node.isConnected){node.querySelector('.bubble').textContent=e.message;node.classList.add('error')}}}\n"
    '\n'
    "async function login(){const username=document.getElementById('username').value.trim(),key=document.getElementById('key').value;try{const d=await api('/api/login',{method:'POST',body:JSON.stringify({username:username,password:key})});localStorage.setItem('workspace.lastUsername',username);document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';if(d.legacy_history_migrated)showToast('Legacy local history migrated to this account');await initializeWorkspace()}catch(e){document.getElementById('loginErr').textContent=e.message}}\n"
    "async function logout(){try{await api('/api/logout',{method:'POST',body:JSON.stringify({})})}catch(e){}state.currentConversationId=null;state.conversations=[];closeAccountMenu();document.getElementById('login').classList.remove('hidden');document.getElementById('key').value='';showEmpty()}\n"
    '\n'
    "function closeAccountMenu(){document.getElementById('accountMenu').classList.remove('open')}\n"
    "function closeUserAdmin(){document.getElementById('userAdminModal').classList.remove('open')}\n"
    "function closePasswordModal(){document.getElementById('passwordModal').classList.remove('open')}\n"
    'function userRow(user){const row=document.createElement(\'div\');row.className=\'user-admin-row\';const profile=document.createElement(\'div\');profile.className=\'user-admin-profile\';const name=document.createElement(\'div\');name.className=\'user-admin-name\';name.textContent=user.display_name||user.username;const meta=document.createElement(\'div\');meta.className=\'user-admin-meta\';meta.textContent=\'@\'+user.username+(user.department?\' · \'+user.department:\'\');profile.append(name,meta);const display=document.createElement(\'input\');display.value=user.display_name||\'\';display.placeholder=\'Display name\';const role=document.createElement(\'select\');role.innerHTML=\'<option value="user">User</option><option value="admin">Admin</option>\';role.value=user.role;const enabled=document.createElement(\'label\');enabled.className=\'user-admin-meta\';const check=document.createElement(\'input\');check.type=\'checkbox\';check.checked=!!user.enabled;enabled.append(check,document.createTextNode(\' Enabled\'));const save=document.createElement(\'button\');save.type=\'button\';save.className=\'soft-btn\';save.textContent=\'Save\';save.onclick=async()=>{try{await api(\'/api/users/\'+encodeURIComponent(user.user_id),{method:\'POST\',body:JSON.stringify({display_name:display.value,role:role.value,enabled:check.checked})});showToast(\'User updated\');await loadUsers();await loadSession()}catch(e){showToast(e.message)}};row.append(profile,display,role,enabled,save);return row}\n'
    'async function loadUsers(){const wrap=document.getElementById(\'userAdminUsers\');wrap.innerHTML=\'<div class="library-empty">Loading users…</div>\';try{const d=await api(\'/api/users\');state.adminUsers=d.users||[];wrap.innerHTML=\'\';for(const user of state.adminUsers)wrap.appendChild(userRow(user));if(!state.adminUsers.length)wrap.innerHTML=\'<div class="library-empty">No users found.</div>\'}catch(e){state.adminUsers=[];wrap.innerHTML=\'<div class="library-empty"></div>\';wrap.firstChild.textContent=e.message}}\n'
    "async function openUserAdmin(){closeAccountMenu();if(state.session?.role!=='admin'){showToast('Administrator role required');return}document.getElementById('userAdminModal').classList.add('open');await loadUsers();await loadExternalIdentities()}\n"
    "async function createUser(e){e.preventDefault();try{await api('/api/users',{method:'POST',body:JSON.stringify({username:document.getElementById('newUsername').value,display_name:document.getElementById('newDisplayName').value,department:document.getElementById('newDepartment').value,title:document.getElementById('newTitle').value,role:document.getElementById('newRole').value,password:document.getElementById('newUserPassword').value})});e.target.reset();showToast('Account created');await loadUsers()}catch(err){showToast(err.message)}}\n"
    "async function changePassword(e){e.preventDefault();const next=document.getElementById('newPassword').value,confirm=document.getElementById('confirmPassword').value;if(next!==confirm){showToast('New passwords do not match');return}try{await api('/api/account/password',{method:'POST',body:JSON.stringify({current_password:document.getElementById('currentPassword').value,new_password:next})});closePasswordModal();document.getElementById('passwordForm').reset();state.currentConversationId=null;state.conversations=[];document.getElementById('login').classList.remove('hidden');document.getElementById('key').value='';showEmpty();showToast('Password changed. Sign in again.')}catch(err){showToast(err.message)}}\n"
    '\n'
    "async function initializeWorkspace(){await Promise.all([loadCapabilities(),loadSession(),loadConversations('')]);const remembered=localStorage.getItem('workspace.currentConversationId');if(remembered&&state.conversations.some(x=>x.conversation_id===remembered)){try{await openConversation(remembered);return}catch(e){}}newChat()}\n"
    '\n'
    '\n'
    "state.historyView='active';\n"
    'state.menuConversationId=null;\n'
    'state.currentConversationArchived=false;\n'
    '\n'
    'function conversationById(id){return state.conversations.find(item=>item.conversation_id===id)||null}\n'
    "function closeConversationMenu(){document.getElementById('conversationMenu').classList.remove('open');state.menuConversationId=null}\n"
    "function closeRenameConversation(){document.getElementById('renameConversationModal').classList.remove('open')}\n"
    "function closeDeleteConversation(){document.getElementById('deleteConversationModal').classList.remove('open')}\n"
    "function syncArchiveNav(){const b=document.getElementById('archivedChatsBtn');b.classList.toggle('selected',state.historyView==='archived');b.title=state.historyView==='archived'?'Back to active chats':'View archived chats'}\n"
    "function syncArchivedComposer(){input.disabled=!!state.currentConversationArchived;document.getElementById('sendBtn').disabled=!!state.currentConversationArchived;input.placeholder=state.currentConversationArchived?'Restore this chat to continue':'Ask WorkSpace'}\n"
    "function dateBucket(value){const d=new Date(value);if(Number.isNaN(d.getTime()))return 'Older';const now=new Date(),day=new Date(d),today=new Date(now);day.setHours(0,0,0,0);today.setHours(0,0,0,0);const diff=Math.round((today-day)/86400000);if(diff<=0)return 'Today';if(diff===1)return 'Yesterday';if(diff<=7)return 'Previous 7 days';return 'Older'}\n"
    "function appendTimeGroups(container,items){const order=['Today','Yesterday','Previous 7 days','Older'],groups=new Map(order.map(k=>[k,[]]));for(const item of items)(groups.get(dateBucket(item.updated_at))||groups.get('Older')).push(item);for(const key of order){const rows=groups.get(key);if(!rows.length)continue;const h=document.createElement('div');h.className='history-time-heading';h.textContent=key;container.appendChild(h);for(const item of rows)container.appendChild(buildConversationRow(item))}}\n"
    'function buildConversationRow(item){const row=document.createElement(\'div\');row.className=\'conversation-row\'+(item.conversation_id===state.currentConversationId?\' active\':\'\');row.dataset.id=item.conversation_id;const icon=document.createElement(\'span\');icon.className=\'conversation-icon\';icon.innerHTML=svgChat();const title=document.createElement(\'span\');title.className=\'conversation-title\';title.textContent=item.title;title.title=item.title;row.append(icon,title);if(item.archived){const archived=document.createElement(\'span\');archived.className=\'archive-indicator\';archived.textContent=\'Archived\';row.appendChild(archived)}const more=document.createElement(\'button\');more.type=\'button\';more.className=\'conversation-more-btn\';more.setAttribute(\'aria-label\',\'Conversation actions\');more.innerHTML=\'<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>\';more.onclick=e=>{e.stopPropagation();openConversationMenu(item.conversation_id,more)};row.appendChild(more);row.onclick=()=>openConversation(item.conversation_id);return row}\n'
    "function renderHistoryList(){const pinned=document.getElementById('pinnedList'),history=document.getElementById('historyList'),section=document.getElementById('pinnedSection');pinned.innerHTML='';history.innerHTML='';syncArchiveNav();if(state.searchQuery){section.classList.add('hidden');document.getElementById('historyHeading').textContent='Search results';for(const item of state.conversations)history.appendChild(buildConversationRow(item))}else if(state.historyView==='archived'){section.classList.add('hidden');document.getElementById('historyHeading').textContent='Archived';appendTimeGroups(history,state.conversations)}else{const p=state.conversations.filter(x=>x.pinned&&!x.archived),normal=state.conversations.filter(x=>!x.pinned&&!x.archived);section.classList.toggle('hidden',p.length===0);document.getElementById('historyHeading').textContent='Chats';for(const item of p)pinned.appendChild(buildConversationRow(item));appendTimeGroups(history,normal)}if(!state.conversations.length){const e=document.createElement('div');e.className='history-empty';e.textContent=state.searchQuery?'No matching chats':(state.historyView==='archived'?'No archived chats':'No saved chats yet');history.appendChild(e)}}\n"
    "async function loadConversations(query=state.searchQuery){state.searchQuery=String(query||'').trim();const params=new URLSearchParams();if(state.searchQuery){params.set('q',state.searchQuery);params.set('view','all')}else params.set('view',state.historyView);const d=await api('/api/conversations?'+params.toString());state.conversations=d.conversations||[];renderHistoryList()}\n"
    "async function openConversation(id){const d=await api('/api/conversations/'+encodeURIComponent(id));state.currentConversationId=d.conversation_id;state.currentConversationArchived=!!d.archived;localStorage.setItem('workspace.currentConversationId',d.conversation_id);document.getElementById('conversationName').textContent=(d.title||'Chat')+(d.archived?' · Archived':'');messages.innerHTML='';for(const m of d.messages||[]){if(m.role==='user')addMessage('You',m.content,'user');else addMessage('WorkSpace',m.content,m.status==='failed'?'error':'')}if(!(d.messages||[]).length)showEmpty();syncArchivedComposer();renderHistoryList();if(window.innerWidth<=760)setSidebarCollapsed(true)}\n"
    "function newChat(){state.currentConversationId=null;state.currentConversationArchived=false;localStorage.removeItem('workspace.currentConversationId');document.getElementById('conversationName').textContent='New chat';messages.innerHTML='';showEmpty();syncArchivedComposer();if(state.historyView!=='active'){state.historyView='active';state.searchQuery='';const q=document.getElementById('historySearchInput');if(q)q.value='';loadConversations('').catch(()=>{})}else renderHistoryList();input.focus();if(window.innerWidth<=760)setSidebarCollapsed(true)}\n"
    "function openSearch(){if(state.sidebarCollapsed)setSidebarCollapsed(false);const box=document.getElementById('historySearchBox');box.classList.remove('hidden');setTimeout(()=>document.getElementById('historySearchInput').focus(),40)}\n"
    "function closeSearch(){state.searchQuery='';const inputEl=document.getElementById('historySearchInput');inputEl.value='';document.getElementById('historySearchBox').classList.add('hidden');loadConversations('').catch(()=>{})}\n"
    "async function toggleArchivedView(){state.searchQuery='';const q=document.getElementById('historySearchInput');if(q)q.value='';document.getElementById('historySearchBox').classList.add('hidden');state.historyView=state.historyView==='archived'?'active':'archived';await loadConversations('')}\n"
    "function openConversationMenu(id,button){const item=conversationById(id);if(!item)return;state.menuConversationId=id;const menu=document.getElementById('conversationMenu'),pin=document.getElementById('conversationPinAction'),archive=document.getElementById('conversationArchiveAction');pin.textContent=item.pinned?'Unpin':'Pin';pin.classList.toggle('hidden',!!item.archived);archive.textContent=item.archived?'Restore':'Archive';const r=button.getBoundingClientRect();menu.classList.add('open');const width=190,height=158;menu.style.left=Math.max(8,Math.min(r.right-width,window.innerWidth-width-8))+'px';menu.style.top=Math.max(8,Math.min(r.bottom+4,window.innerHeight-height-8))+'px'}\n"
    "function beginRenameConversation(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();state.menuConversationId=item.conversation_id;const inputEl=document.getElementById('renameConversationInput');inputEl.value=item.title||'';document.getElementById('renameConversationModal').classList.add('open');setTimeout(()=>{inputEl.focus();inputEl.select()},30)}\n"
    "async function submitRenameConversation(e){e.preventDefault();const id=state.menuConversationId,title=document.getElementById('renameConversationInput').value.trim();if(!id)return;try{const d=await api('/api/conversations/'+encodeURIComponent(id)+'/rename',{method:'POST',body:JSON.stringify({title})});closeRenameConversation();if(state.currentConversationId===id)document.getElementById('conversationName').textContent=d.title+(d.archived?' · Archived':'');showToast('Chat renamed');await loadConversations()}catch(err){showToast(err.message)}}\n"
    'async function toggleConversationPin(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();await setPinned(item.conversation_id,!item.pinned)}\n'
    "async function toggleConversationArchive(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();try{await api('/api/conversations/'+encodeURIComponent(item.conversation_id)+'/archive',{method:'POST',body:JSON.stringify({archived:!item.archived})});if(state.currentConversationId===item.conversation_id){state.currentConversationId=null;state.currentConversationArchived=false;localStorage.removeItem('workspace.currentConversationId');document.getElementById('conversationName').textContent='New chat';messages.innerHTML='';showEmpty();syncArchivedComposer()}showToast(item.archived?'Chat restored':'Chat archived');await loadConversations()}catch(err){showToast(err.message)}}\n"
    "function beginDeleteConversation(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();state.menuConversationId=item.conversation_id;document.getElementById('deleteConversationCopy').textContent='Permanently delete “'+item.title+'” and all saved messages? This cannot be undone.';document.getElementById('deleteConversationModal').classList.add('open')}\n"
    "async function confirmDeleteConversation(){const id=state.menuConversationId;if(!id)return;try{await api('/api/conversations/'+encodeURIComponent(id)+'/delete',{method:'POST',body:JSON.stringify({})});closeDeleteConversation();if(state.currentConversationId===id){state.currentConversationId=null;state.currentConversationArchived=false;localStorage.removeItem('workspace.currentConversationId');document.getElementById('conversationName').textContent='New chat';messages.innerHTML='';showEmpty();syncArchivedComposer()}state.menuConversationId=null;showToast('Chat deleted');await loadConversations()}catch(err){showToast(err.message)}}\n"
    '\n'
    "document.getElementById('archivedChatsBtn').onclick=()=>toggleArchivedView().catch(e=>showToast(e.message));\n"
    "document.getElementById('conversationRenameAction').onclick=beginRenameConversation;\n"
    "document.getElementById('conversationPinAction').onclick=()=>toggleConversationPin().catch(e=>showToast(e.message));\n"
    "document.getElementById('conversationArchiveAction').onclick=()=>toggleConversationArchive().catch(e=>showToast(e.message));\n"
    "document.getElementById('conversationDeleteAction').onclick=beginDeleteConversation;\n"
    "document.getElementById('renameConversationForm').addEventListener('submit',submitRenameConversation);\n"
    "document.getElementById('closeRenameConversation').onclick=closeRenameConversation;\n"
    "document.getElementById('cancelRenameConversation').onclick=closeRenameConversation;\n"
    "document.getElementById('closeDeleteConversation').onclick=closeDeleteConversation;\n"
    "document.getElementById('cancelDeleteConversation').onclick=closeDeleteConversation;\n"
    "document.getElementById('confirmDeleteConversation').onclick=()=>confirmDeleteConversation().catch(e=>showToast(e.message));\n"
    "document.addEventListener('click',e=>{if(!e.target.closest('#conversationMenu')&&!e.target.closest('.conversation-more-btn'))closeConversationMenu()});\n"
    'syncArchivedComposer();\n'
    'syncArchiveNav();\n'
    '\n'
    '\n'
    'state.projects=[];\n'
    'state.selectedProjectId=null;\n'
    'state.projectMenuId=null;\n'
    'state.projectEditId=null;\n'
    '\n'
    'function projectById(id){return state.projects.find(p=>p.project_id===id)||null}\n'
    'function folderSvg(){return \'<svg viewBox="0 0 24 24"><path d="M3 6h7l2 2h9v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>\'}\n'
    "function closeProjectMenu(){document.getElementById('projectMenu').classList.remove('open');state.projectMenuId=null}\n"
    "function closeProjectEdit(){document.getElementById('projectEditModal').classList.remove('open');state.projectEditId=null}\n"
    "function closeProjectDelete(){document.getElementById('projectDeleteModal').classList.remove('open')}\n"
    "function closeMoveProject(){document.getElementById('moveProjectModal').classList.remove('open')}\n"
    'function renderProjects(){const wrap=document.getElementById(\'projectsList\');wrap.innerHTML=\'\';for(const p of state.projects){const row=document.createElement(\'div\');row.className=\'project-row\'+(p.project_id===state.selectedProjectId?\' active\':\'\');const icon=document.createElement(\'span\');icon.className=\'project-folder\';icon.innerHTML=folderSvg();const name=document.createElement(\'span\');name.className=\'project-name\';name.textContent=p.name;name.title=p.name;const count=document.createElement(\'span\');count.className=\'project-count\';count.textContent=String(p.conversation_count||0);const more=document.createElement(\'button\');more.type=\'button\';more.className=\'project-more-btn\';more.setAttribute(\'aria-label\',\'Project actions\');more.innerHTML=\'<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>\';more.onclick=e=>{e.stopPropagation();openProjectMenu(p.project_id,more)};row.append(icon,name,count,more);row.onclick=()=>selectProject(p.project_id);wrap.appendChild(row)}if(!state.projects.length){const e=document.createElement(\'div\');e.className=\'history-empty\';e.textContent=\'No projects yet\';wrap.appendChild(e)}}\n'
    "async function loadProjects(){const d=await api('/api/projects');state.projects=d.projects||[];if(state.selectedProjectId&&!state.projects.some(p=>p.project_id===state.selectedProjectId))state.selectedProjectId=null;renderProjects()}\n"
    "async function selectProject(id){state.selectedProjectId=state.selectedProjectId===id?null:id;state.searchQuery='';state.historyView='active';const q=document.getElementById('historySearchInput');if(q)q.value='';document.getElementById('historySearchBox').classList.add('hidden');renderProjects();await loadConversations('');if(window.innerWidth<=760)setSidebarCollapsed(true)}\n"
    "function clearProjectSelection(){if(!state.selectedProjectId)return;state.selectedProjectId=null;renderProjects();loadConversations('').catch(e=>showToast(e.message))}\n"
    "function openProjectMenu(id,button){const p=projectById(id);if(!p)return;state.projectMenuId=id;const menu=document.getElementById('projectMenu'),r=button.getBoundingClientRect();menu.classList.add('open');menu.style.left=Math.max(8,Math.min(r.right-170,window.innerWidth-178))+'px';menu.style.top=Math.max(8,Math.min(r.bottom+4,window.innerHeight-92))+'px'}\n"
    "function beginCreateProject(){closeProjectMenu();state.projectEditId=null;document.getElementById('projectEditTitle').textContent='New project';document.getElementById('projectNameInput').value='';document.getElementById('projectEditModal').classList.add('open');setTimeout(()=>document.getElementById('projectNameInput').focus(),30)}\n"
    "function beginRenameProject(){const p=projectById(state.projectMenuId);if(!p)return;closeProjectMenu();state.projectEditId=p.project_id;document.getElementById('projectEditTitle').textContent='Rename project';document.getElementById('projectNameInput').value=p.name;document.getElementById('projectEditModal').classList.add('open');setTimeout(()=>{const e=document.getElementById('projectNameInput');e.focus();e.select()},30)}\n"
    "async function submitProjectEdit(e){e.preventDefault();const name=document.getElementById('projectNameInput').value.trim(),editing=!!state.projectEditId,editId=state.projectEditId;try{if(editing)await api('/api/projects/'+encodeURIComponent(editId)+'/rename',{method:'POST',body:JSON.stringify({name})});else await api('/api/projects',{method:'POST',body:JSON.stringify({name})});closeProjectEdit();showToast(editing?'Project renamed':'Project created');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}\n"
    "function beginDeleteProject(){const p=projectById(state.projectMenuId);if(!p)return;closeProjectMenu();state.projectMenuId=p.project_id;document.getElementById('projectDeleteCopy').textContent='Delete “'+p.name+'”? Its chats will be kept and moved back to the main chat list.';document.getElementById('projectDeleteModal').classList.add('open')}\n"
    "async function confirmProjectDelete(){const id=state.projectMenuId;if(!id)return;try{const d=await api('/api/projects/'+encodeURIComponent(id)+'/delete',{method:'POST',body:JSON.stringify({})});closeProjectDelete();if(state.selectedProjectId===id)state.selectedProjectId=null;state.projectMenuId=null;showToast('Project deleted · '+String(d.detached_conversations||0)+' chats kept');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}\n"
    "function openMoveProject(){const item=conversationById(state.menuConversationId);if(!item)return;closeConversationMenu();state.menuConversationId=item.conversation_id;const wrap=document.getElementById('moveProjectList');wrap.innerHTML='';const choices=[{project_id:'',name:'No project'},...state.projects];for(const p of choices){const b=document.createElement('button');b.type='button';b.className='move-project-row'+((item.project_id||'')===(p.project_id||'')?' selected':'');b.innerHTML=folderSvg();const s=document.createElement('span');s.textContent=p.name;b.appendChild(s);b.onclick=()=>moveConversationToProject(item.conversation_id,p.project_id||null);wrap.appendChild(b)}document.getElementById('moveProjectModal').classList.add('open')}\n"
    "async function moveConversationToProject(conversationId,projectId){try{await api('/api/conversations/'+encodeURIComponent(conversationId)+'/project',{method:'POST',body:JSON.stringify({project_id:projectId})});closeMoveProject();showToast(projectId?'Chat moved to project':'Chat removed from project');await loadProjects();await loadConversations()}catch(err){showToast(err.message)}}\n"
    '\n'
    "function renderHistoryList(){const pinned=document.getElementById('pinnedList'),history=document.getElementById('historyList'),section=document.getElementById('pinnedSection');pinned.innerHTML='';history.innerHTML='';syncArchiveNav();renderProjects();const selected=projectById(state.selectedProjectId);if(state.searchQuery){section.classList.add('hidden');document.getElementById('historyHeading').textContent='Search results';for(const item of state.conversations)history.appendChild(buildConversationRow(item))}else if(state.historyView==='archived'){section.classList.add('hidden');document.getElementById('historyHeading').textContent=selected?selected.name+' · Archived':'Archived';appendTimeGroups(history,state.conversations)}else if(selected){section.classList.add('hidden');document.getElementById('historyHeading').textContent=selected.name;appendTimeGroups(history,state.conversations)}else{const p=state.conversations.filter(x=>x.pinned&&!x.archived),normal=state.conversations.filter(x=>!x.pinned&&!x.archived);section.classList.toggle('hidden',p.length===0);document.getElementById('historyHeading').textContent='Chats';for(const item of p)pinned.appendChild(buildConversationRow(item));appendTimeGroups(history,normal)}if(!state.conversations.length){const e=document.createElement('div');e.className='history-empty';e.textContent=state.searchQuery?'No matching chats':selected?'No chats in this project':(state.historyView==='archived'?'No archived chats':'No saved chats yet');history.appendChild(e)}}\n"
    "async function loadConversations(query=state.searchQuery){state.searchQuery=String(query||'').trim();const params=new URLSearchParams();if(state.searchQuery){params.set('q',state.searchQuery);params.set('view','all')}else{params.set('view',state.historyView);if(state.selectedProjectId)params.set('project',state.selectedProjectId)}const d=await api('/api/conversations?'+params.toString());state.conversations=d.conversations||[];renderHistoryList()}\n"
    "async function initializeWorkspace(){await Promise.all([loadCapabilities(),loadSession(),loadProjects()]);await loadConversations('');const remembered=localStorage.getItem('workspace.currentConversationId');if(remembered){try{await openConversation(remembered);return}catch(e){localStorage.removeItem('workspace.currentConversationId')}}newChat()}\n"
    '\n'
    "document.getElementById('addProjectBtn').onclick=beginCreateProject;\n"
    "document.getElementById('projectRenameAction').onclick=beginRenameProject;\n"
    "document.getElementById('projectDeleteAction').onclick=beginDeleteProject;\n"
    "document.getElementById('projectEditForm').addEventListener('submit',submitProjectEdit);\n"
    "document.getElementById('closeProjectEdit').onclick=closeProjectEdit;\n"
    "document.getElementById('cancelProjectEdit').onclick=closeProjectEdit;\n"
    "document.getElementById('closeProjectDelete').onclick=closeProjectDelete;\n"
    "document.getElementById('cancelProjectDelete').onclick=closeProjectDelete;\n"
    "document.getElementById('confirmProjectDelete').onclick=()=>confirmProjectDelete().catch(e=>showToast(e.message));\n"
    "document.getElementById('conversationMoveAction').onclick=openMoveProject;\n"
    "document.getElementById('closeMoveProject').onclick=closeMoveProject;\n"
    "document.addEventListener('click',e=>{if(!e.target.closest('#projectMenu')&&!e.target.closest('.project-more-btn'))closeProjectMenu()});\n"
    '\n'
    '\n'
    "state.authProviders={local:true,external:[],broker_url:''};\n"
    'state.adminUsers=[];\n'
    '\n'
    "function providerLabel(provider){return provider==='google'?'Google':provider==='github'?'GitHub':provider==='line'?'LINE':provider}\n"
    "function providerButton(provider){const b=document.createElement('button');b.type='button';b.className='soft-btn external-login-btn';b.textContent='Continue with '+providerLabel(provider);b.onclick=()=>beginExternalLogin(provider);return b}\n"
    "async function loadAuthProviders(){try{const d=await api('/api/auth/providers');state.authProviders=d;const list=document.getElementById('externalLoginList');list.innerHTML='';for(const provider of d.external||[])list.appendChild(providerButton(provider));const shown=(d.external||[]).length>0;document.getElementById('externalLoginDivider').classList.toggle('hidden',!shown);document.getElementById('externalLoginNote').classList.toggle('hidden',!shown)}catch(e){state.authProviders={local:true,external:[],broker_url:''}}}\n"
    "function beginExternalLogin(provider){const d=state.authProviders||{};if(!(d.external||[]).includes(provider)||!d.broker_url){document.getElementById('loginErr').textContent='External login provider is not configured';return}const target=d.broker_url.replace(/\\/$/,'')+'/auth/start/'+encodeURIComponent(provider)+'?return_to='+encodeURIComponent(window.location.origin);window.location.assign(target)}\n"
    "async function completeExternalLoginFromFragment(){const raw=window.location.hash||'';const prefix='#workspace_external_ticket=';if(!raw.startsWith(prefix))return false;const ticket=decodeURIComponent(raw.slice(prefix.length));history.replaceState(null,'',window.location.pathname+window.location.search);try{const d=await api('/api/external/login',{method:'POST',body:JSON.stringify({ticket})});if(d.status==='pending'){document.getElementById('loginErr').textContent='Identity verified. An administrator must approve this account before first login.';return true}document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';await initializeWorkspace();return true}catch(e){document.getElementById('loginErr').textContent=e.message;return true}}\n"
    "function externalIdentityRow(item){const row=document.createElement('div');row.className='external-identity-row';const provider=document.createElement('div');provider.className='external-provider';provider.textContent=providerLabel(item.provider);const info=document.createElement('div');const name=document.createElement('div');name.textContent=item.display_name||'Verified identity';const status=document.createElement('div');status.className='external-status';status.textContent=item.status;info.append(name,status);const select=document.createElement('select');const blank=document.createElement('option');blank.value='';blank.textContent='Select local user';select.appendChild(blank);for(const user of state.adminUsers||[]){if(!user.enabled)continue;const o=document.createElement('option');o.value=user.user_id;o.textContent=(user.display_name||user.username)+' (@'+user.username+')';if(item.user_id===user.user_id)o.selected=true;select.appendChild(o)}const actions=document.createElement('div');actions.className='external-actions';const approve=document.createElement('button');approve.type='button';approve.className='soft-btn';approve.textContent=item.status==='approved'?'Rebind':'Approve';approve.onclick=async()=>{if(!select.value){showToast('Select a local WorkSpace user first');return}try{await api('/api/external-identities/'+encodeURIComponent(item.identity_id)+'/approve',{method:'POST',body:JSON.stringify({user_id:select.value})});showToast('External identity approved');await loadExternalIdentities()}catch(e){showToast(e.message)}};const reject=document.createElement('button');reject.type='button';reject.className='soft-btn';reject.textContent='Reject';reject.onclick=async()=>{try{await api('/api/external-identities/'+encodeURIComponent(item.identity_id)+'/reject',{method:'POST',body:JSON.stringify({})});showToast('External identity rejected');await loadExternalIdentities()}catch(e){showToast(e.message)}};actions.append(approve,reject);row.append(provider,info,select,actions);return row}\n"
    "async function loadExternalIdentities(){const wrap=document.getElementById('externalIdentityList');if(!wrap)return;try{const d=await api('/api/external-identities');wrap.innerHTML='';for(const item of d.identities||[])wrap.appendChild(externalIdentityRow(item));if(!(d.identities||[]).length){const empty=document.createElement('div');empty.className='library-empty';empty.textContent='No external identities have attempted login yet.';wrap.appendChild(empty)}}catch(e){wrap.innerHTML='';const empty=document.createElement('div');empty.className='library-empty';empty.textContent=e.message;wrap.appendChild(empty)}}\n"
    '\n'
    "document.getElementById('sidebarToggle').onclick=toggleSidebar;\n"
    "document.getElementById('mobileMenuBtn').onclick=()=>setSidebarCollapsed(false);\n"
    "document.getElementById('newChatBtn').onclick=newChat;\n"
    "document.getElementById('historySearchBtn').onclick=openSearch;\n"
    "document.getElementById('clearHistorySearch').onclick=closeSearch;\n"
    "document.getElementById('historySearchInput').addEventListener('input',e=>{clearTimeout(state.searchTimer);state.searchTimer=setTimeout(()=>loadConversations(e.target.value).catch(err=>showToast(err.message)),180)});\n"
    "document.getElementById('accountBtn').onclick=()=>document.getElementById('accountMenu').classList.toggle('open');\n"
    "document.getElementById('manageUsersBtn').onclick=openUserAdmin;\n"
    "document.getElementById('changePasswordBtn').onclick=()=>{closeAccountMenu();document.getElementById('passwordModal').classList.add('open');document.getElementById('currentPassword').focus()};\n"
    "document.getElementById('logoutBtn').onclick=logout;\n"
    "document.getElementById('loginBtn').onclick=login;\n"
    "document.getElementById('key').addEventListener('keydown',e=>{if(e.key==='Enter')login()});\n"
    "document.getElementById('username').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('key').focus()});\n"
    "document.getElementById('closeUserAdmin').onclick=closeUserAdmin;\n"
    "document.getElementById('closePasswordModal').onclick=closePasswordModal;\n"
    "document.getElementById('createUserForm').addEventListener('submit',createUser);\n"
    "document.getElementById('passwordForm').addEventListener('submit',changePassword);\n"
    "document.getElementById('plusBtn').onclick=()=>document.getElementById('plusMenu').classList.toggle('open');\n"
    "document.getElementById('clearMode').onclick=()=>setMode('chat');\n"
    "document.getElementById('fileInput').addEventListener('change',e=>{state.selectedFiles=Array.from(e.target.files||[]).slice(0,8);renderAttachments();e.target.value=''});\n"
    "document.getElementById('closeLibrary').onclick=()=>document.getElementById('libraryModal').classList.remove('open');\n"
    "document.getElementById('libraryCancel').onclick=()=>document.getElementById('libraryModal').classList.remove('open');\n"
    "document.getElementById('libraryAdd').onclick=applyLibrary;\n"
    "document.getElementById('micBtn').onclick=()=>cap('voice_input').enabled?showToast('Local voice runtime is enabled but no recorder is bound to this build.'):unavailable('voice_input');\n"
    "document.getElementById('sendBtn').onclick=sendMsg;\n"
    "input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg()}});\n"
    "input.addEventListener('input',()=>{input.style.height='auto';input.style.height=Math.min(input.scrollHeight,170)+'px'});\n"
    "for(const row of document.querySelectorAll('.menu-row[data-action]'))row.onclick=()=>{const action=row.dataset.action;if(action==='upload'){if(!cap('upload').enabled)return unavailable('upload');document.getElementById('fileInput').click();document.getElementById('plusMenu').classList.remove('open')}else if(action==='library')openLibrary().catch(e=>showToast(e.message));else if(action==='web_search'||action==='deep_research')setMode(action);else unavailable(action)};\n"
    "document.addEventListener('click',e=>{if(!e.target.closest('#plusMenu')&&!e.target.closest('#plusBtn'))document.getElementById('plusMenu').classList.remove('open');if(!e.target.closest('.account-wrap'))document.getElementById('accountMenu').classList.remove('open')});\n"
    '\n'
    'applySidebarState();\n'
    "(async()=>{document.getElementById('username').value=localStorage.getItem('workspace.lastUsername')||'admin';await loadAuthProviders();if(await completeExternalLoginFromFragment())return;try{await api('/api/session');document.getElementById('login').classList.add('hidden');await initializeWorkspace()}catch(e){}})();\n"
    '</script>\n'
    '\n'
    '<button type="button" class="workflow-studio-btn" id="workflowStudioBtn">Workflow Studio</button>\n'
    '<div class="workflow-studio-overlay" id="workflowStudioOverlay" role="dialog" aria-modal="true" aria-labelledby="workflowStudioTitle">\n'
    '  <div class="workflow-studio-panel">\n'
    '    <div class="workflow-studio-head">\n'
    '      <h2 id="workflowStudioTitle">Workflow Studio</h2>\n'
    '      <button type="button" class="soft-btn" id="workflowStudioClose">Close</button>\n'
    '    </div>\n'
    '    <div class="workflow-studio-note">Describe the process in plain language. WorkSpace compiles a design-only graph; creating a diagram never grants execution authority.</div>\n'
    '    <textarea class="workflow-studio-input" id="workflowDescription" maxlength="8000" placeholder="Example: Every Monday, collect project metrics, validate them, flag risks, prepare a management report, require manager approval, then publish the approved report."></textarea>\n'
    '\n'
    '    <div class="workflow-library-toolbar">\n'
    '      <button type="button" class="soft-btn" id="workflowLibraryBtn">My Workflows</button>\n'
    '      <input id="workflowDraftTitle" maxlength="120" placeholder="Workflow name">\n'
    '      <button type="button" class="soft-btn" id="workflowDraftCreateBtn">Save new</button>\n'
    '      <button type="button" class="soft-btn" id="workflowDraftSaveBtn" disabled>Save revision</button>\n'
    '      <button type="button" class="soft-btn" id="workflowDraftDuplicateBtn" disabled>Duplicate</button>\n'
    '      <button type="button" class="soft-btn" id="workflowDraftArchiveBtn" disabled>Archive</button>\n'
    '      <span class="workflow-library-authority">Draft = design only · execution authority unchanged</span>\n'
    '      <div class="workflow-library-current" id="workflowDraftCurrent" style="width:100%">Unsaved workflow</div>\n'
    '    </div>\n'
    '    <div class="workflow-library-drawer workflow-hidden" id="workflowLibraryDrawer">\n'
    '      <div class="workflow-library-filters">\n'
    '        <input id="workflowLibrarySearch" maxlength="200" placeholder="Search workflows">\n'
    '        <select id="workflowLibraryView"><option value="active">Active</option><option value="archived">Archived</option><option value="all">All</option></select>\n'
    '        <button type="button" class="soft-btn" id="workflowLibraryRefresh">Refresh</button>\n'
    '      </div>\n'
    '      <div class="workflow-library-list" id="workflowLibraryList"><div class="library-empty">Open My Workflows to load saved designs.</div></div>\n'
    '      <div class="workflow-library-version-list" id="workflowDraftVersions"></div>\n'
    '    </div>\n'
    '\n'
    '    <div class="workflow-studio-actions">\n'
    '      <button type="button" class="soft-btn primary" id="workflowCompileBtn">Compile workflow</button>\n'
    '      <span class="workflow-chip" id="workflowStatus">Design only · no execution</span>\n'
    '      <span class="workflow-chip" id="workflowRisk">Risk: —</span>\n'
    '      <span class="workflow-chip" id="workflowDataClass">Data: —</span>\n'
    '    </div>\n'
    '    \n'
    '<div class="workflow-v4-box" id="workflowV4Box">\n'
    '  <div class="workflow-v4-row">\n'
    '    <button type="button" class="soft-btn" id="workflowV4PrepareBtn">Prepare V4</button>\n'
    '    <button type="button" class="soft-btn workflow-v4-danger" id="workflowV4StartBtn" disabled>Authorize &amp; start</button>\n'
    '    <span class="workflow-v4-separator"></span>\n'
    '    <input class="workflow-v4-input" id="workflowV4TaskId" placeholder="TASK-YYYYMMDD-0001" aria-label="Workflow task ID">\n'
    '    <button type="button" class="soft-btn" id="workflowV4LoadBtn">Load state</button>\n'
    '    <span class="workflow-v4-separator"></span>\n'
    '    <button type="button" class="soft-btn" id="workflowV4ApproveBtn" disabled>Approve checkpoint</button>\n'
    '    <button type="button" class="soft-btn workflow-v4-danger" id="workflowV4RejectBtn" disabled>Reject checkpoint</button>\n'
    '    <span class="workflow-chip" id="workflowV4Status">ver.0.0.2 · V4: not prepared</span>\n'
    '  </div>\n'
    '  <div class="workflow-v4-detail" id="workflowV4Detail">Manual low-risk workflows may use deterministic validation branches, persistent approval checkpoints, and one bounded two-lane parallel DAG (Research → Presentation per lane) with a verified join. Scheduling, event triggers, arbitrary conditions, nested parallelism and new capabilities remain blocked.</div>\n'
    '</div>\n'
    '<div class="workflow-grid">\n'
    '      <div class="workflow-card">\n'
    '        <h3>Diagram</h3>\n'
    '        <div class="workflow-diagram" id="workflowDiagram"><div class="library-empty">Describe a workflow and compile it.</div></div>\n'
    '      </div>\n'
    '      <div class="workflow-card">\n'
    '        <h3>Steps</h3>\n'
    '        <div id="workflowSteps"><div class="library-empty">No workflow compiled.</div></div>\n'
    '      </div>\n'
    '      <div class="workflow-card">\n'
    '        <div class="workflow-tabs">\n'
    '          <button type="button" class="soft-btn" data-workflow-tab="mermaid">Mermaid</button>\n'
    '          <button type="button" class="soft-btn" data-workflow-tab="json">Contract JSON</button>\n'
    '        </div>\n'
    '        <pre class="workflow-code" id="workflowMermaid"></pre>\n'
    '        <pre class="workflow-code workflow-hidden" id="workflowJson"></pre>\n'
    '      </div>\n'
    '      <div class="workflow-card">\n'
    '        <h3>Safety / warnings</h3>\n'
    '        <div id="workflowWarnings"><div class="library-empty">No warnings.</div></div>\n'
    '      </div>\n'
    '    </div>\n'
    '  </div>\n'
    '</div>\n'
    '<script>\n'
    '(function(){\n'
    "const overlay=document.getElementById('workflowStudioOverlay'),desc=document.getElementById('workflowDescription'),diagram=document.getElementById('workflowDiagram'),steps=document.getElementById('workflowSteps'),warnings=document.getElementById('workflowWarnings'),mermaid=document.getElementById('workflowMermaid'),json=document.getElementById('workflowJson');\n"
    "function openWorkflowStudio(){overlay.classList.add('open');desc.focus()}\n"
    "function closeWorkflowStudio(){overlay.classList.remove('open')}\n"
    'function textNode(tag,text,cls){const e=document.createElement(tag);if(cls)e.className=cls;e.textContent=text;return e}\n'
    'function renderWorkflow(d){const c=d.contract||{};document.getElementById(\'workflowRisk\').textContent=\'Risk: \'+(c.risk_level||\'—\');document.getElementById(\'workflowDataClass\').textContent=\'Data: \'+(c.data_class||\'—\');document.getElementById(\'workflowStatus\').textContent=d.execution_authorized?\'Execution authorized\':\'Design only · no execution\';diagram.innerHTML=d.diagram?.svg||\'<div class="library-empty">Diagram unavailable.</div>\';steps.innerHTML=\'\';for(const n of c.nodes||[]){const row=document.createElement(\'div\');row.className=\'workflow-step\';row.append(textNode(\'strong\',n.label||n.id),textNode(\'span\',(n.kind||\'\')+\' · \'+(n.action||\'\')+(n.approval_required?\' · approval required\':\'\')));steps.append(row)}if(!(c.nodes||[]).length)steps.append(textNode(\'div\',\'No steps.\',\'library-empty\'));warnings.innerHTML=\'\';for(const w of c.warnings||[])warnings.append(textNode(\'div\',w,\'workflow-warning\'));if(!(c.warnings||[]).length)warnings.append(textNode(\'div\',\'No warnings.\',\'library-empty\'));mermaid.textContent=d.diagram?.mermaid||\'\';json.textContent=JSON.stringify(c,null,2)}\n'
    "async function compileWorkflow(){const description=desc.value.trim();if(!description){showToast('Describe the workflow first');return}const btn=document.getElementById('workflowCompileBtn');btn.disabled=true;btn.textContent='Compiling…';try{const d=await api('/api/workflows/compile',{method:'POST',body:JSON.stringify({description,language:document.getElementById('lang').value})});renderWorkflow(d);showToast('Workflow compiled — design only')}catch(e){showToast(e.message)}finally{btn.disabled=false;btn.textContent='Compile workflow'}}\n"
    "document.getElementById('workflowStudioBtn').onclick=openWorkflowStudio;document.getElementById('workflowStudioClose').onclick=closeWorkflowStudio;document.getElementById('workflowCompileBtn').onclick=compileWorkflow;overlay.addEventListener('click',e=>{if(e.target===overlay)closeWorkflowStudio()});for(const b of document.querySelectorAll('[data-workflow-tab]'))b.onclick=()=>{const target=b.dataset.workflowTab;mermaid.classList.toggle('workflow-hidden',target!=='mermaid');json.classList.toggle('workflow-hidden',target!=='json')};\n"
    '})();\n'
    '</script><script>\n'
    '(function(){\n'
    'let active=null;\n'
    "const prepareBtn=document.getElementById('workflowV4PrepareBtn'),startBtn=document.getElementById('workflowV4StartBtn'),loadBtn=document.getElementById('workflowV4LoadBtn'),approveBtn=document.getElementById('workflowV4ApproveBtn'),rejectBtn=document.getElementById('workflowV4RejectBtn'),taskInput=document.getElementById('workflowV4TaskId'),status=document.getElementById('workflowV4Status'),detail=document.getElementById('workflowV4Detail'),json=document.getElementById('workflowJson');\n"
    "function currentContract(){const raw=(json.textContent||'').trim();if(!raw)throw new Error('Compile a workflow before preparing V3');const parsed=JSON.parse(raw);if(!parsed||typeof parsed!=='object')throw new Error('Workflow contract is unavailable');return parsed}\n"
    'function resetButtons(){startBtn.disabled=true;approveBtn.disabled=true;rejectBtn.disabled=true}\n'
    "function setState(text,cls,message){status.textContent='ver.0.0.2 · V4: '+text;status.classList.remove('workflow-v4-ok','workflow-v4-paused','workflow-v4-blocked');if(cls)status.classList.add(cls);detail.textContent=message||''}\n"
    "function applyState(d){active=active||{};active.task_id=d.task_id||active.task_id;taskInput.value=active.task_id||'';active.checkpoint=d.checkpoint||null;resetButtons();if(d.status==='prepared'&&active.approval_fingerprint){startBtn.disabled=false;setState('prepared','workflow-v4-ok','Task '+d.task_id+' is prepared. Initial administrator authorization is still required.')}else if(d.status==='paused'&&d.checkpoint){approveBtn.disabled=false;rejectBtn.disabled=false;setState('paused at '+d.checkpoint.node_id,'workflow-v4-paused','Checkpoint: '+(d.checkpoint.label||d.checkpoint.node_id)+' · revision '+(d.revision||'—')+' · choose APPROVE or REJECT.')}else if(d.status==='completed'){setState('completed','workflow-v4-ok','Task '+d.task_id+' completed with required validators passed.')}else if(d.status==='rejected'){setState('rejected','workflow-v4-blocked','Task '+d.task_id+' stopped on the rejected approval branch.')}else if(d.status==='blocked'||d.status==='failed'){setState(d.status,'workflow-v4-blocked',(d.terminal_reason||'runtime gate')+(d.error?' · '+d.error:''));}else{setState(d.status||'unknown','', 'Task '+(d.task_id||'')+' · current node '+(d.current_node||'—'));}}\n"
    "prepareBtn.addEventListener('click',async()=>{prepareBtn.disabled=true;resetButtons();active=null;setState('checking admission','', 'Compiling the diagram contract into the bounded V4 state machine.');try{const d=await api('/api/workflows/prepare-dispatch',{method:'POST',body:JSON.stringify({contract:currentContract(),language:document.getElementById('lang').value,output_format:'pptx'})});active={task_id:d.task_id,approval_fingerprint:d.approval_fingerprint,checkpoint:null};taskInput.value=d.task_id;applyState(d);showToast('V4 prepared — execution is still unauthorized')}catch(e){setState('blocked','workflow-v4-blocked',e.message);showToast('V4 admission blocked: '+e.message)}finally{prepareBtn.disabled=false}});\n"
    "startBtn.addEventListener('click',async()=>{if(!active||!active.approval_fingerprint){showToast('Prepare V4 first');return}const typed=window.prompt('Execution is a side effect. Type AUTHORIZE exactly to start '+active.task_id+'.');if(typed!=='AUTHORIZE'){showToast('Execution not authorized');return}resetButtons();prepareBtn.disabled=true;setState('running','', 'Running until completion or the next persistent approval checkpoint.');try{const d=await api('/api/workflows/'+encodeURIComponent(active.task_id)+'/execute',{method:'POST',body:JSON.stringify({approval_fingerprint:active.approval_fingerprint,confirmation:'AUTHORIZE'})});active.approval_fingerprint=null;applyState(d);showToast(d.status==='paused'?'Workflow paused for approval':'Workflow state: '+d.status)}catch(e){setState('failed','workflow-v4-blocked',e.message);showToast('V4 start failed: '+e.message)}finally{prepareBtn.disabled=false}});\n"
    "loadBtn.addEventListener('click',async()=>{const taskId=(taskInput.value||'').trim();if(!taskId){showToast('Enter a task ID');return}resetButtons();try{const d=await api('/api/workflows/'+encodeURIComponent(taskId)+'/state');active={task_id:taskId,approval_fingerprint:null,checkpoint:d.checkpoint||null};applyState(d);showToast('Workflow state loaded')}catch(e){setState('load failed','workflow-v4-blocked',e.message);showToast('Cannot load workflow state: '+e.message)}});\n"
    "async function decide(decision){if(!active||!active.checkpoint){showToast('Load a paused checkpoint first');return}const typed=window.prompt('Type '+decision+' exactly for checkpoint '+active.checkpoint.node_id+'.');if(typed!==decision){showToast('Checkpoint decision cancelled');return}resetButtons();setState('resuming','', decision+' accepted locally; server is verifying the exact checkpoint fingerprint.');try{const d=await api('/api/workflows/'+encodeURIComponent(active.task_id)+'/checkpoint',{method:'POST',body:JSON.stringify({checkpoint_fingerprint:active.checkpoint.fingerprint,decision:decision,confirmation:decision})});applyState(d);showToast('Checkpoint decision recorded: '+decision)}catch(e){setState('checkpoint failed','workflow-v4-blocked',e.message);showToast('Checkpoint transition failed: '+e.message)}}\n"
    "approveBtn.addEventListener('click',()=>decide('APPROVE'));rejectBtn.addEventListener('click',()=>decide('REJECT'));\n"
    "const compileBtn=document.getElementById('workflowCompileBtn');if(compileBtn)compileBtn.addEventListener('click',()=>{active=null;resetButtons();setState('not prepared','', 'Compile result changed; V4 requires a fresh admission and fingerprint. Existing paused tasks remain recoverable by Task ID.')});\n"
    '})();\n'
    '</script><script>\n'
    '(function(){\n'
    "const surface=document.getElementById('securityAnalystSurface'),badge=document.getElementById('securityAnalystBadge'),healthChip=document.getElementById('securityHealthChip'),highChip=document.getElementById('securityHighCriticalChip'),coverageChip=document.getElementById('securityCoverageChip');\n"
    "let securityOpen=false,activeTab='overview',pollHandle=null,previousTitle='',offsets={network:0,findings:0,events:0,reports:0};\n"
    'const PAGE=50;\n'
    "function sText(value,fallback='—'){return value===null||value===undefined||value===''?fallback:String(value)}\n"
    "function sCell(row,value){const td=document.createElement('td');td.textContent=sText(value);row.appendChild(td);return td}\n"
    "function sEmpty(tbody,message,cols){tbody.innerHTML='';const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=cols;td.className='security-empty';td.textContent=message;tr.appendChild(td);tbody.appendChild(tr)}\n"
    "function sRows(tbody,items,cols,render){tbody.innerHTML='';if(!items.length){sEmpty(tbody,'No data available.',cols);return}for(const item of items){const tr=document.createElement('tr');render(tr,item);tbody.appendChild(tr)}}\n"
    "function sJson(value){try{return JSON.stringify(value)}catch(e){return '—'}}\n"
    "function setBadge(summary){const health=sText(summary.health,'unknown'),count=Number(summary.high_critical_count||0);badge.textContent=health+' · '+count;healthChip.textContent='Health: '+health;highChip.textContent='High/Critical: '+count;const coverage=summary.latest_hourly&&summary.latest_hourly.coverage_pct!==undefined?summary.latest_hourly.coverage_pct+'%':'—';coverageChip.textContent='Coverage: '+coverage;document.getElementById('securityOverviewHealth').textContent=health;document.getElementById('securityOverviewHighCritical').textContent=String(count);document.getElementById('securityOverviewAssets').textContent=String(summary.enabled_asset_count||0);document.getElementById('securityOverviewCoverage').textContent=coverage}\n"
    "async function refreshSecurityBadge(){try{const d=await api('/api/security/summary');setBadge(d)}catch(e){badge.textContent='unavailable'} }\n"
    "async function loadOverview(){const [summary,findings]=await Promise.all([api('/api/security/summary'),api('/api/security/findings?limit=5&offset=0')]);setBadge(summary);const body=document.getElementById('securityOverviewFindings');sRows(body,findings.items||[],5,(tr,item)=>{sCell(tr,item.finding_id);sCell(tr,item.severity);sCell(tr,item.status);sCell(tr,item.category);sCell(tr,item.last_seen)})}\n"
    "function renderPager(id,key,count,load){const wrap=document.getElementById(id);wrap.innerHTML='';const prev=document.createElement('button');prev.type='button';prev.className='soft-btn';prev.textContent='Previous';prev.disabled=offsets[key]===0;prev.onclick=()=>{offsets[key]=Math.max(0,offsets[key]-PAGE);load()};const label=document.createElement('span');label.textContent='Offset '+offsets[key]+' · '+count+' rows';const next=document.createElement('button');next.type='button';next.className='soft-btn';next.textContent='Next';next.disabled=count<PAGE||offsets[key]>=10000;next.onclick=()=>{offsets[key]=Math.min(10000,offsets[key]+PAGE);load()};wrap.append(prev,label,next)}\n"
    "async function loadNetwork(){const d=await api('/api/security/network?limit='+PAGE+'&offset='+offsets.network),body=document.getElementById('securityNetworkRows');sRows(body,d.items||[],7,(tr,item)=>{sCell(tr,item.observed_at);sCell(tr,item.asset_id);sCell(tr,item.collector);sCell(tr,item.metric);sCell(tr,item.status);sCell(tr,sJson(item.value)+(item.unit?' '+item.unit:''));sCell(tr,item.evidence_ref)});renderPager('securityNetworkPager','network',(d.items||[]).length,loadNetwork)}\n"
    "async function loadFindings(){const d=await api('/api/security/findings?limit='+PAGE+'&offset='+offsets.findings),body=document.getElementById('securityFindingRows');sRows(body,d.items||[],6,(tr,item)=>{tr.className='clickable';sCell(tr,item.finding_id);sCell(tr,item.severity);sCell(tr,item.status);sCell(tr,item.category);sCell(tr,(item.asset_refs||[]).join(', '));sCell(tr,item.last_seen);tr.onclick=()=>{document.getElementById('securityFindingDetail').textContent=JSON.stringify(item,null,2)}});renderPager('securityFindingPager','findings',(d.items||[]).length,loadFindings)}\n"
    "async function loadEvents(){const d=await api('/api/security/events?limit='+PAGE+'&offset='+offsets.events),body=document.getElementById('securityEventRows');sRows(body,d.items||[],7,(tr,item)=>{sCell(tr,item.observed_at);sCell(tr,item.source_id);sCell(tr,item.source_type);sCell(tr,item.severity);sCell(tr,item.category);sCell(tr,item.parser_version);sCell(tr,item.evidence_ref)});renderPager('securityEventPager','events',(d.items||[]).length,loadEvents)}\n"
    "async function loadAssets(){const d=await api('/api/security/assets'),body=document.getElementById('securityAssetRows');sRows(body,d.items||[],7,(tr,item)=>{sCell(tr,item.asset_id);sCell(tr,item.role);sCell(tr,item.enabled?'yes':'no');sCell(tr,item.data_class);sCell(tr,(item.collector_capabilities||[]).join(', '));sCell(tr,item.observed_state?.last_status);sCell(tr,item.observed_state?.last_observed_at)})}\n"
    "async function loadReports(){const d=await api('/api/security/reports?limit='+PAGE+'&offset='+offsets.reports),body=document.getElementById('securityReportRows');sRows(body,d.items||[],6,(tr,item)=>{sCell(tr,item.archive_id);sCell(tr,item.period_kind+' · '+item.period_key);sCell(tr,item.status);sCell(tr,item.attempt);sCell(tr,item.updated_at);sCell(tr,item.manifest_sha256)});renderPager('securityReportPager','reports',(d.items||[]).length,loadReports)}\n"
    "function adminKV(grid,key,value){const box=document.createElement('div');box.className='security-kv';const b=document.createElement('b');b.textContent=key;const span=document.createElement('span');span.textContent=typeof value==='object'?JSON.stringify(value):sText(value);box.append(b,span);grid.appendChild(box)}\n"
    "async function loadAdmin(){const grid=document.getElementById('securityAdminGrid');grid.innerHTML='';try{const d=await api('/api/security/admin');for(const key of ['config_state','database_available','schema_version_db','enabled','allow_real_network','asset_count','secret_boundary_configured','read_only_ui','mutations_exposed','autonomous_remediation','autonomous_pcap','passive_sensors_optional'])adminKV(grid,key,d[key]);adminKV(grid,'policy',d.policy||{})}catch(e){adminKV(grid,'Administration',e.message)}}\n"
    'const loaders={overview:loadOverview,network:loadNetwork,findings:loadFindings,events:loadEvents,assets:loadAssets,reports:loadReports,admin:loadAdmin};\n'
    "async function loadActive(){try{await loaders[activeTab]()}catch(e){showToast('Security Analyst: '+e.message)}}\n"
    "function schedulePoll(){if(pollHandle){clearInterval(pollHandle);pollHandle=null}if(!securityOpen||document.visibilityState!=='visible')return;pollHandle=setInterval(()=>{if(securityOpen&&document.visibilityState==='visible')refreshSecurityBadge()},30000)}\n"
    "function activateTab(name){activeTab=name;for(const b of document.querySelectorAll('[data-security-tab]'))b.classList.toggle('active',b.dataset.securityTab===name);for(const v of document.querySelectorAll('[data-security-view]'))v.classList.toggle('active',v.dataset.securityView===name);loadActive()}\n"
    "function openSecurity(){securityOpen=true;previousTitle=document.getElementById('conversationName').textContent;document.body.classList.add('security-analyst-open');surface.classList.add('open');document.getElementById('conversationName').textContent='Security Analyst';document.getElementById('securityAdminTab').classList.toggle('hidden',state.session?.role!=='admin');refreshSecurityBadge();loadActive();schedulePoll();if(window.innerWidth<=760)setSidebarCollapsed(true)}\n"
    "function closeSecurity(){if(!securityOpen)return;securityOpen=false;surface.classList.remove('open');document.body.classList.remove('security-analyst-open');document.getElementById('conversationName').textContent=previousTitle||'New chat';schedulePoll()}\n"
    "document.getElementById('securityAnalystBtn').onclick=openSecurity;document.getElementById('securityAnalystClose').onclick=closeSecurity;for(const b of document.querySelectorAll('[data-security-tab]'))b.onclick=()=>activateTab(b.dataset.securityTab);document.addEventListener('visibilitychange',schedulePoll);for(const id of ['newChatBtn','historyList','pinnedList','projectsList','archivedChatsBtn']){const e=document.getElementById(id);if(e)e.addEventListener('click',closeSecurity)}document.getElementById('loginBtn').addEventListener('click',()=>setTimeout(refreshSecurityBadge,800));setTimeout(refreshSecurityBadge,1000);\n"
    '})();\n'
    '</script><script>\n'
    '(function(){\n'
    "const tab=document.getElementById('securityConfigTab'),view=document.getElementById('securityConfigView'),status=document.getElementById('secCfgStatus'),assets=document.getElementById('secCfgAssets'),meta=document.getElementById('secCfgMeta');\n"
    'let loadedEnvelope=null;\n'
    'function cfgText(id){return document.getElementById(id).value.trim()}\n'
    'function cfgBool(id){return !!document.getElementById(id).checked}\n'
    'function cfgNumber(id){return Number(document.getElementById(id).value)}\n'
    "function setStatus(message,ok=null){status.textContent=message;status.style.borderColor=ok===true?'#315a46':ok===false?'#694040':'#30343b'}\n"
    "function metaKV(key,value){const box=document.createElement('div');box.className='security-kv';const b=document.createElement('b');b.textContent=key;const s=document.createElement('span');s.textContent=value===undefined||value===null?'—':String(value);box.append(b,s);meta.appendChild(box)}\n"
    "function selectedCaps(){return Array.from(document.querySelectorAll('#secCfgCaps input:checked')).map(x=>x.value)}\n"
    "function setSelectedCaps(values){const set=new Set(values||[]);for(const x of document.querySelectorAll('#secCfgCaps input'))x.checked=set.has(x.value)}\n"
    'function assetEditor(item={}){const box=document.createElement(\'div\');box.className=\'security-asset-editor\';box.innerHTML=\'<div class="security-asset-head"><b>Approved asset</b><button class="soft-btn secAssetRemove" type="button">Remove</button></div><div class="security-config-grid"><div class="security-config-field"><label>Asset ID</label><input class="secAssetId" maxlength="128"></div><div class="security-config-field"><label>Role</label><input class="secAssetRole" maxlength="64" placeholder="router / switch / server"></div><div class="security-config-field"><label>Management host</label><input class="secAssetHost" maxlength="253" placeholder="192.168.11.1"></div><div class="security-config-field"><label>Data class</label><select class="secAssetClass"><option>public</option><option>internal</option><option selected>confidential</option><option>restricted</option><option>secret</option></select></div><div class="security-switch"><span>Enabled</span><input class="secAssetEnabled" type="checkbox" checked></div><div class="security-config-field"><label>Allowed TCP ports</label><input class="secAssetPorts" placeholder="443, 22"></div><div class="security-config-field wide"><label>Collector capabilities</label><div class="security-cap-list secAssetCaps"><label><input type="checkbox" value="snmpv3_read"> SNMPv3 read</label><label><input type="checkbox" value="local_net_read"> Local read</label><label><input type="checkbox" value="icmp_echo"> ICMP</label><label><input type="checkbox" value="tcp_connect"> TCP connect</label><label><input type="checkbox" value="fixed_readonly_adapter"> Fixed read-only adapter</label></div></div><div class="security-config-field wide"><label>Credential reference (opaque; SNMPv3 only)</label><input class="secAssetCredential" placeholder="secret-ref:router-snmpv3" autocomplete="off"></div></div>\';\n'
    "box.querySelector('.secAssetId').value=item.asset_id||'';box.querySelector('.secAssetRole').value=item.role||'';box.querySelector('.secAssetHost').value=item.management_host||'';box.querySelector('.secAssetClass').value=item.data_class||'confidential';box.querySelector('.secAssetEnabled').checked=item.enabled!==false;box.querySelector('.secAssetPorts').value=(item.allowed_tcp_ports||[]).join(', ');box.querySelector('.secAssetCredential').value=item.credential_ref||'';const caps=new Set(item.collector_capabilities||[]);for(const x of box.querySelectorAll('.secAssetCaps input'))x.checked=caps.has(x.value);box.querySelector('.secAssetRemove').onclick=()=>box.remove();return box}\n"
    "function readAssets(){return Array.from(assets.querySelectorAll('.security-asset-editor')).map(box=>({asset_id:box.querySelector('.secAssetId').value.trim(),role:box.querySelector('.secAssetRole').value.trim(),management_host:box.querySelector('.secAssetHost').value.trim(),collector_capabilities:Array.from(box.querySelectorAll('.secAssetCaps input:checked')).map(x=>x.value),allowed_tcp_ports:box.querySelector('.secAssetPorts').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number),data_class:box.querySelector('.secAssetClass').value,enabled:box.querySelector('.secAssetEnabled').checked,credential_ref:box.querySelector('.secAssetCredential').value.trim()||null}))}\n"
    "function currentPayload(){return {enabled:cfgBool('secCfgEnabled'),allow_real_network:cfgBool('secCfgRealNetwork'),database_path:cfgText('secCfgDatabase'),secret_directory:cfgText('secCfgSecretDir')||null,policy:{profile_id:cfgText('secCfgProfile'),network_scope:'approved_inventory_only',read_only:true,production_safety_profile:'non_disruptive_v1',allow_active_liveness:cfgBool('secCfgActiveLiveness'),bandwidth_measurement_mode:'counter_only',packet_analysis_mode:'passive_only',max_workers:cfgNumber('secCfgWorkers'),timeout_seconds:cfgNumber('secCfgTimeout'),max_retries:cfgNumber('secCfgRetries'),max_catch_up_runs:1,allowed_capabilities:selectedCaps()},assets:readAssets()}}\n"
    "function fill(payload){document.getElementById('secCfgEnabled').checked=!!payload.enabled;document.getElementById('secCfgRealNetwork').checked=!!payload.allow_real_network;document.getElementById('secCfgDatabase').value=payload.database_path||'';document.getElementById('secCfgSecretDir').value=payload.secret_directory||'';const p=payload.policy||{};document.getElementById('secCfgProfile').value=p.profile_id||'default';document.getElementById('secCfgWorkers').value=p.max_workers??4;document.getElementById('secCfgTimeout').value=p.timeout_seconds??3;document.getElementById('secCfgRetries').value=p.max_retries??1;document.getElementById('secCfgActiveLiveness').checked=!!p.allow_active_liveness;setSelectedCaps(p.allowed_capabilities||['snmpv3_read','local_net_read']);assets.innerHTML='';for(const item of payload.assets||[])assets.appendChild(assetEditor(item))}\n"
    "function renderGovernance(g={}){const box=document.getElementById('secGovernanceState');box.innerHTML='';const add=(k,v)=>{const el=document.createElement('div');el.className='security-kv';const b=document.createElement('b');b.textContent=k;const s=document.createElement('span');s.textContent=v===undefined||v===null?'—':String(v);el.append(b,s);box.appendChild(el)};add('Revision',g.revision??0);add('State',g.change_state||'unknown');add('Drift',g.drift_detected?'DETECTED':'No');add('Audit chain',g.audit_chain_valid===false?'INVALID':'Valid');const adopt=document.getElementById('secCfgAdopt');adopt.disabled=!g.adoption_required;document.getElementById('secCfgSave').disabled=g.change_state==='drift'||g.change_state==='audit_invalid'||g.adoption_required===true}\n"
    "function renderEnvelope(d){loadedEnvelope=d;fill(d.config||{});meta.innerHTML='';metaKV('State',d.state);metaKV('Config path',d.config_path);metaKV('Path source',d.path_source);metaKV('Policy fingerprint',d.summary?.policy_fingerprint);renderGovernance(d.governance||{});const blocked=['drift','audit_invalid','adoption_required'].includes(d.governance?.change_state);setStatus(blocked?'CONFIGURATION GOVERNANCE BLOCKED: '+d.governance.change_state:(d.state==='configured'?'Configuration loaded.':'Safe defaults loaded but not saved.'),!blocked)}\n"
    "async function loadConfig(){try{setStatus('Loading configuration…');renderEnvelope(await api('/api/security/config'))}catch(e){setStatus('Load failed: '+e.message,false)}}\n"
    "async function postConfig(path,payload){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(payload)});let d={};try{d=await r.json()}catch(e){}if(!r.ok)throw new Error(d.error||d.code||('HTTP '+r.status));return d}\n"
    "async function validateConfig(){try{setStatus('Validating…');const d=await postConfig('/api/security/config/validate',{config:currentPayload()});setStatus('VALID\\nPolicy: '+d.summary.policy_fingerprint+'\\nAssets: '+d.summary.asset_count+'\\nReady: '+d.readiness.ready,true)}catch(e){setStatus('INVALID\\n'+e.message,false)}}\n"
    "async function readiness(){try{setStatus('Checking local readiness…');const d=await postConfig('/api/security/config/readiness',{});const lines=['Ready: '+d.ready,'Network test executed: '+d.network_test_executed,'Secret values read: '+d.secret_values_read];for(const x of d.issues||[])lines.push('BLOCKER '+x.code+': '+x.message);for(const x of d.warnings||[])lines.push('WARNING '+x.code+': '+x.message);setStatus(lines.join('\\n'),d.ready)}catch(e){setStatus('Readiness failed: '+e.message,false)}}\n"
    "function changeReason(){return document.getElementById('secCfgChangeReason').value.trim()}\n"
    'function currentRevision(){return Number(loadedEnvelope?.governance?.revision??0)}\n'
    "async function saveConfig(){const payload=currentPayload(),reason=changeReason();if(!reason){setStatus('SAVE BLOCKED\\nChange reason is required.',false);return}if(loadedEnvelope?.governance?.adoption_required){setStatus('SAVE BLOCKED\\nAdopt the existing configuration before changing it.',false);return}if(payload.policy.allow_active_liveness&&!confirm('Active liveness generates ICMP/TCP probe traffic to explicitly approved inventory only. Continue saving?'))return;if(payload.allow_real_network&&!confirm('Allow read-only network collection for explicitly approved assets? Saving does not start collection.'))return;try{setStatus('Validating and saving governed revision…');const d=await postConfig('/api/security/config/save',{config:payload,expected_revision:currentRevision(),change_reason:reason});document.getElementById('secCfgChangeReason').value='';setStatus('SAVED REVISION '+d.revision+'\\nPolicy: '+d.summary.policy_fingerprint+'\\nReady: '+d.readiness.ready,true);await loadConfig();if(typeof refreshSecurityBadge==='function')refreshSecurityBadge()}catch(e){setStatus('SAVE BLOCKED\\n'+e.message,false)}}\n"
    "async function loadHistory(){try{const d=await api('/api/security/config/history?limit=50'),box=document.getElementById('secCfgHistoryList');box.innerHTML='';for(const item of d.history||[]){const row=document.createElement('div');row.className='security-history-row';const b=document.createElement('b');b.textContent='Revision '+item.revision+(item.source_revision?' · from '+item.source_revision:'');const s=document.createElement('span');s.textContent=(item.created_at||'')+' · '+(item.actor||'')+' · '+(item.reason||'');row.append(b,s);box.appendChild(row)}if(!(d.history||[]).length)box.textContent='No governed revisions yet.'}catch(e){setStatus('HISTORY FAILED\\n'+e.message,false)}}\n"
    "async function adoptExisting(){const reason=changeReason();if(!reason){setStatus('ADOPTION BLOCKED\\nChange reason is required.',false);return}if(!confirm('Adopt the currently stored configuration as revision 1 after administrative review?'))return;try{const d=await postConfig('/api/security/config/adopt',{change_reason:reason});document.getElementById('secCfgChangeReason').value='';setStatus('ADOPTED REVISION '+d.revision,true);await loadConfig();await loadHistory()}catch(e){setStatus('ADOPTION BLOCKED\\n'+e.message,false)}}\n"
    "async function rollbackConfig(){const reason=changeReason(),source=Number(document.getElementById('secCfgRollbackRevision').value);if(!reason){setStatus('ROLLBACK BLOCKED\\nChange reason is required.',false);return}if(!Number.isInteger(source)||source<1){setStatus('ROLLBACK BLOCKED\\nChoose a valid source revision.',false);return}if(!confirm('Rollback from revision '+source+' by creating a new audited revision?'))return;try{const d=await postConfig('/api/security/config/rollback',{source_revision:source,expected_revision:currentRevision(),change_reason:reason});document.getElementById('secCfgChangeReason').value='';setStatus('ROLLBACK SAVED AS REVISION '+d.revision,true);await loadConfig();await loadHistory()}catch(e){setStatus('ROLLBACK BLOCKED\\n'+e.message,false)}}\n"
    "function openConfig(){if(state.session?.role!=='admin'){showToast('Administrator role required');return}for(const b of document.querySelectorAll('[data-security-tab]'))b.classList.toggle('active',b===tab);for(const v of document.querySelectorAll('[data-security-view]'))v.classList.toggle('active',v===view);loadConfig()}\n"
    "function updateAccess(){tab.classList.toggle('hidden',state.session?.role!=='admin')}\n"
    "tab.onclick=openConfig;document.getElementById('secCfgAddAsset').onclick=()=>assets.appendChild(assetEditor());document.getElementById('secCfgReload').onclick=loadConfig;document.getElementById('secCfgValidate').onclick=validateConfig;document.getElementById('secCfgReadiness').onclick=readiness;document.getElementById('secCfgSave').onclick=saveConfig;document.getElementById('secCfgHistory').onclick=loadHistory;document.getElementById('secCfgAdopt').onclick=adoptExisting;document.getElementById('secCfgRollback').onclick=rollbackConfig;document.getElementById('securityAnalystBtn').addEventListener('click',updateAccess);document.getElementById('loginBtn').addEventListener('click',()=>setTimeout(updateAccess,500));updateAccess();\n"
    '})();\n'
    '</script><script>\n'
    '(function(){\n'
    "const tab=document.getElementById('securitySocTab');\n"
    'if(!tab)return;\n'
    "const allowedTruth=new Set(['VERIFIED FACT','INFERENCE','UNKNOWN']);\n"
    'function clearRows(body){while(body.firstChild)body.removeChild(body.firstChild)}\n'
    "function emptyRow(body,cols,message){clearRows(body);const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=cols;td.className='security-empty';td.textContent=message;tr.appendChild(td);body.appendChild(tr)}\n"
    "function cell(tr,value){const td=document.createElement('td');td.textContent=value===null||value===undefined||value===''?'—':String(value);tr.appendChild(td);return td}\n"
    "function refs(value){return Array.isArray(value)?value.join(', '):'—'}\n"
    "function renderRisk(d){const risk=d&&d.risk_summary||{};document.getElementById('securitySocTodayRisk').textContent=String(risk.today_open_high_critical??0);document.getElementById('securitySoc7dRisk').textContent=String(risk.rolling_7d_open_high_critical??0);document.getElementById('securitySoc30dRisk').textContent=String(risk.rolling_30d_open_high_critical??0);document.getElementById('securitySocDataGaps').textContent=String(risk.today_data_gaps??0)}\n"
    "function renderFindings(items){const body=document.getElementById('securitySocFindingRows');clearRows(body);if(!Array.isArray(items)||!items.length){emptyRow(body,6,'No bounded SOC findings.');return}for(const item of items){const tr=document.createElement('tr');cell(tr,item.finding_id);cell(tr,item.severity);cell(tr,item.status);cell(tr,item.category);cell(tr,item.last_seen);cell(tr,refs(item.evidence_refs));body.appendChild(tr)}}\n"
    "function renderEvidence(items){const body=document.getElementById('securitySocEvidenceRows');clearRows(body);if(!Array.isArray(items)||!items.length){emptyRow(body,1,'No evidence references in this snapshot.');return}for(const ref of items){const tr=document.createElement('tr');cell(tr,ref);body.appendChild(tr)}}\n"
    "function truthClass(state){if(state==='VERIFIED FACT')return 'verified';if(state==='INFERENCE')return 'inference';return 'unknown'}\n"
    "function renderAnalyst(items){const body=document.getElementById('securitySocAnalystRows');clearRows(body);if(!Array.isArray(items)||!items.length){emptyRow(body,3,'No enterprise analyst assessment attached to this deterministic snapshot.');return}for(const item of items){if(!allowedTruth.has(item.truth_state))continue;const tr=document.createElement('tr'),stateCell=document.createElement('td'),badge=document.createElement('span');badge.className='security-truth-state '+truthClass(item.truth_state);badge.textContent=item.truth_state;stateCell.appendChild(badge);tr.appendChild(stateCell);cell(tr,item.statement);cell(tr,refs(item.evidence_ids));body.appendChild(tr)}if(!body.children.length)emptyRow(body,3,'No valid enterprise truth-state findings.')} \n"
    "async function loadSoc(){try{const d=await api('/api/security/soc');renderRisk(d);renderFindings(d.findings);renderEvidence(d.evidence_refs);renderAnalyst(d.analyst_findings)}catch(e){renderRisk({});emptyRow(document.getElementById('securitySocFindingRows'),6,'SOC snapshot unavailable.');emptyRow(document.getElementById('securitySocEvidenceRows'),1,'SOC snapshot unavailable.');emptyRow(document.getElementById('securitySocAnalystRows'),3,'SOC snapshot unavailable.')}}\n"
    "tab.addEventListener('click',loadSoc);\n"
    '})();\n'
    '</script>\n'
    '<script>\n'
    '(function(){\n'
    "const drawer=document.getElementById('workflowLibraryDrawer'),list=document.getElementById('workflowLibraryList'),versions=document.getElementById('workflowDraftVersions'),titleInput=document.getElementById('workflowDraftTitle'),desc=document.getElementById('workflowDescription'),json=document.getElementById('workflowJson'),mermaid=document.getElementById('workflowMermaid'),diagram=document.getElementById('workflowDiagram'),steps=document.getElementById('workflowSteps'),warnings=document.getElementById('workflowWarnings'),currentMeta=document.getElementById('workflowDraftCurrent'),saveBtn=document.getElementById('workflowDraftSaveBtn'),duplicateBtn=document.getElementById('workflowDraftDuplicateBtn'),archiveBtn=document.getElementById('workflowDraftArchiveBtn');\n"
    'let current=null;\n'
    'function el(tag,text,cls){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n}\n'
    "function contractFromCanvas(){const raw=(json.textContent||'').trim();if(!raw)throw new Error('Compile or open a workflow first');const c=JSON.parse(raw);if(!c||typeof c!=='object')throw new Error('Workflow contract unavailable');return c}\n"
    "function currentTitle(contract){return titleInput.value.trim()||String(contract.title||'Untitled workflow').slice(0,120)}\n"
    "function setCurrent(d){current=d||null;if(!d){currentMeta.textContent='Unsaved workflow';saveBtn.disabled=true;duplicateBtn.disabled=true;archiveBtn.disabled=true;archiveBtn.textContent='Archive';return}titleInput.value=d.title||'';currentMeta.textContent=d.draft_id+' · revision '+d.revision+' · '+d.status+' · '+d.content_sha256.slice(0,12)+'…';saveBtn.disabled=d.status!=='active';duplicateBtn.disabled=false;archiveBtn.disabled=false;archiveBtn.textContent=d.status==='archived'?'Restore':'Archive'}\n"
    'function renderDraft(d){setCurrent(d);desc.value=d.description||\'\';const c=d.contract||{};document.getElementById(\'workflowRisk\').textContent=\'Risk: \'+(c.risk_level||\'—\');document.getElementById(\'workflowDataClass\').textContent=\'Data: \'+(c.data_class||\'—\');document.getElementById(\'workflowStatus\').textContent=\'Design only · no execution\';diagram.innerHTML=d.diagram?.svg||\'<div class="library-empty">Diagram unavailable.</div>\';steps.innerHTML=\'\';for(const n of c.nodes||[]){const row=el(\'div\',\'\', \'workflow-step\');row.append(el(\'strong\',n.label||n.id),el(\'span\',(n.kind||\'\')+\' · \'+(n.action||\'\')+(n.approval_required?\' · approval required\':\'\')));steps.append(row)}if(!(c.nodes||[]).length)steps.append(el(\'div\',\'No steps.\',\'library-empty\'));warnings.innerHTML=\'\';for(const w of c.warnings||[])warnings.append(el(\'div\',w,\'workflow-warning\'));if(!(c.warnings||[]).length)warnings.append(el(\'div\',\'No warnings.\',\'library-empty\'));mermaid.textContent=d.diagram?.mermaid||\'\';json.textContent=JSON.stringify(c,null,2)}\n'
    "async function loadVersions(){versions.innerHTML='';if(!current)return;try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/versions');for(const v of d.versions||[])versions.append(el('span','v'+v.revision+' · '+v.origin+' · '+v.content_sha256.slice(0,8),'workflow-library-version'))}catch(e){versions.append(el('span','Version history unavailable: '+e.message,'workflow-warning'))}}\n"
    "async function openDraft(id){try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(id));renderDraft(d.draft);await loadVersions();showToast('Workflow draft opened — execution remains unauthorized')}catch(e){showToast('Cannot open workflow: '+e.message)}}\n"
    "function renderList(rows){list.innerHTML='';for(const d of rows||[]){const b=el('button','', 'workflow-library-item'+(d.status==='archived'?' archived':''));b.type='button';b.append(el('b',d.title),el('span','rev '+d.revision+' · '+d.status+' · '+d.node_count+' nodes'),el('span',(d.risk_level||'—')+' risk · '+(d.data_class||'—')+' data'),el('span',d.updated_at||''));b.onclick=()=>openDraft(d.draft_id);list.append(b)}if(!(rows||[]).length)list.append(el('div','No workflows found.','library-empty'))}\n"
    "async function loadLibrary(){const q=document.getElementById('workflowLibrarySearch').value.trim(),view=document.getElementById('workflowLibraryView').value;try{const d=await api('/api/workflows/drafts?view='+encodeURIComponent(view)+'&q='+encodeURIComponent(q));renderList(d.drafts)}catch(e){list.innerHTML='';list.append(el('div','Load failed: '+e.message,'workflow-warning'))}}\n"
    "async function saveNew(){try{const c=contractFromCanvas();const d=await api('/api/workflows/drafts',{method:'POST',body:JSON.stringify({title:currentTitle(c),description:desc.value,contract:c,origin:'workspace_ai'})});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast('Workflow saved as revision 1')}catch(e){showToast('Save blocked: '+e.message)}}\n"
    "async function saveRevision(){if(!current){showToast('Save a new workflow first');return}try{const c=contractFromCanvas();const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/save',{method:'POST',body:JSON.stringify({expected_revision:current.revision,expected_content_sha256:current.content_sha256,title:currentTitle(c),description:desc.value,contract:c,origin:'human'})});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast('Workflow revision saved')}catch(e){showToast('Revision save blocked: '+e.message+' — reload if this draft changed elsewhere')}}\n"
    "async function duplicateDraft(){if(!current)return;try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/duplicate',{method:'POST',body:'{}'});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast('Independent workflow copy created')}catch(e){showToast('Duplicate blocked: '+e.message)}}\n"
    "async function toggleArchive(){if(!current)return;const action=current.status==='archived'?'restore':'archive';try{const d=await api('/api/workflows/drafts/'+encodeURIComponent(current.draft_id)+'/'+action,{method:'POST',body:'{}'});renderDraft(d.draft);await loadVersions();await loadLibrary();showToast(action==='archive'?'Workflow archived':'Workflow restored')}catch(e){showToast('Lifecycle change blocked: '+e.message)}}\n"
    "document.getElementById('workflowLibraryBtn').onclick=()=>{drawer.classList.toggle('workflow-hidden');if(!drawer.classList.contains('workflow-hidden'))loadLibrary()};document.getElementById('workflowLibraryRefresh').onclick=loadLibrary;document.getElementById('workflowLibrarySearch').addEventListener('keydown',e=>{if(e.key==='Enter')loadLibrary()});document.getElementById('workflowLibraryView').onchange=loadLibrary;document.getElementById('workflowDraftCreateBtn').onclick=saveNew;saveBtn.onclick=saveRevision;duplicateBtn.onclick=duplicateDraft;archiveBtn.onclick=toggleArchive;\n"
    '})();\n'
    '</script><script>\n'
    '(function(){\n'
    "const CONFIRMATION='ENABLE_APPROVED_REAL_NETWORK_MONITORING';\n"
    'const originalFetch=window.fetch.bind(window);\n'
    "function requestPath(input){try{return new URL(typeof input==='string'?input:input.url,window.location.href).pathname}catch(e){return ''}}\n"
    'window.fetch=async function(input,init){\n'
    '  let options=init?{...init}:{};\n'
    "  if(requestPath(input)==='/api/security/config/save' && String(options.method||'GET').toUpperCase()==='POST' && options.body){\n"
    '    try{\n'
    '      const payload=JSON.parse(options.body);\n'
    "      const field=document.getElementById('secCfgStrongConfirmation');\n"
    "      payload.confirmation=field?field.value.trim():'';\n"
    '      options.body=JSON.stringify(payload);\n'
    '    }catch(e){}\n'
    '  }\n'
    '  const response=await originalFetch(input,options);\n'
    "  if(requestPath(input)==='/api/security/config/save' && response.ok){\n"
    "    const field=document.getElementById('secCfgStrongConfirmation');\n"
    "    if(field)field.value='';\n"
    '    window.setTimeout(loadClosureSecurityMeta,50);\n'
    '  }\n'
    '  return response;\n'
    '};\n'
    'function auditText(item){\n'
    "  const changed=Array.isArray(item.changed_sections)?item.changed_sections.join(', '):'—';\n"
    "  const reasons=Array.isArray(item.confirmation_reasons)&&item.confirmation_reasons.length?item.confirmation_reasons.join(', '):'none';\n"
    "  return 'changed='+changed+' · assets='+String(item.asset_count??'—')+' · real_network='+String(!!item.allow_real_network)+' · confirmation='+reasons;\n"
    '}\n'
    'function renderAudit(items){\n'
    "  const root=document.getElementById('secCfgAuditRows');if(!root)return;root.innerHTML='';\n"
    "  if(!items.length){const empty=document.createElement('div');empty.className='security-empty';empty.textContent='No configuration audit records yet.';root.appendChild(empty);return}\n"
    "  for(const item of items){const row=document.createElement('div');row.className='security-audit-row';const b=document.createElement('b');b.textContent=item.recorded_at||'audit';const s=document.createElement('span');s.textContent=auditText(item);row.append(b,s);root.appendChild(row)}\n"
    '}\n'
    'async function loadClosureSecurityMeta(){\n'
    "  try{const r=await originalFetch('/api/security/runtime',{credentials:'same-origin'});const d=await r.json();if(r.ok){const sha=document.getElementById('secCfgRuntimeSha'),gw=document.getElementById('secCfgRuntimeGateway');if(sha)sha.textContent=d.source_sha||'unknown';if(gw)gw.textContent=d.gateway||'unknown'}}catch(e){}\n"
    "  try{const r=await originalFetch('/api/security/config/audit?limit=20',{credentials:'same-origin'});const d=await r.json();if(r.ok)renderAudit(Array.isArray(d.items)?d.items:[])}catch(e){}\n"
    '}\n'
    "const reload=document.getElementById('secCfgAuditReload');if(reload)reload.onclick=()=>loadClosureSecurityMeta();\n"
    "const tab=document.getElementById('securityConfigTab');if(tab)tab.addEventListener('click',()=>window.setTimeout(loadClosureSecurityMeta,0));\n"
    "const real=document.getElementById('secCfgRealNetwork');if(real)real.addEventListener('change',()=>{const field=document.getElementById('secCfgStrongConfirmation');if(real.checked&&field&&!field.value)field.placeholder=CONFIRMATION});\n"
    '})();\n'
    '</script><script>\n'
    '(function(){\n'
    "const root=document.getElementById('secCfgAssets');\n"
    "const configTab=document.getElementById('securityConfigTab');\n"
    'if(!root||!configTab)return;\n'
    "let configFingerprint='';\n"
    'let snapshotLoading=false;\n'
    "function toast(message){if(typeof window.showToast==='function')window.showToast(message)}\n"
    "function confirmation(){const field=document.getElementById('secCfgStrongConfirmation');return field?field.value.trim():''}\n"
    "async function jsonRequest(path,options={}){const response=await fetch(path,{credentials:'same-origin',...options});let data={};try{data=await response.json()}catch(e){}if(!response.ok){const error=new Error(data.error||data.code||('HTTP '+response.status));error.status=response.status;error.code=data.code||'';throw error}return data}\n"
    "async function loadFingerprint(){if(snapshotLoading)return;snapshotLoading=true;try{const data=await jsonRequest('/api/security/assets/config');configFingerprint=String(data.config_fingerprint||'');decorateEditors()}catch(e){configFingerprint=''}finally{snapshotLoading=false}}\n"
    "function assetFrom(box){return {asset_id:box.querySelector('.secAssetId').value.trim(),role:box.querySelector('.secAssetRole').value.trim(),management_host:box.querySelector('.secAssetHost').value.trim(),collector_capabilities:Array.from(box.querySelectorAll('.secAssetCaps input:checked')).map(x=>x.value),allowed_tcp_ports:box.querySelector('.secAssetPorts').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number),data_class:box.querySelector('.secAssetClass').value,enabled:box.querySelector('.secAssetEnabled').checked,credential_ref:box.querySelector('.secAssetCredential').value.trim()||null}}\n"
    "function stateNode(box){let node=box.querySelector('.security-asset-exact-state');if(!node){node=document.createElement('span');node.className='security-asset-exact-state';const head=box.querySelector('.security-asset-head');if(head)head.appendChild(node)}return node}\n"
    "function setState(box,message,kind=''){const node=stateNode(box);node.textContent=message;node.className='security-asset-exact-state'+(kind?' '+kind:'')}\n"
    "async function handleConflict(box,error){if(error.status===409||error.code==='SECURITY_ASSET_CONFIG_STALE'){setState(box,'Stale configuration — reload before retry','warn');toast('Approved asset changed elsewhere. Reload Configuration before retry.');await loadFingerprint();const reload=document.getElementById('secCfgReload');if(reload)reload.click();return true}return false}\n"
    "async function saveAsset(box){if(!configFingerprint){setState(box,'Load asset snapshot first','warn');await loadFingerprint();if(!configFingerprint)return}setState(box,'Saving exact asset…');try{const data=await jsonRequest('/api/security/assets/upsert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset:assetFrom(box),expected_config_fingerprint:configFingerprint,confirmation:confirmation()})});configFingerprint=String(data.config_fingerprint||configFingerprint);setState(box,(data.action||'saved')+' · network execution=false','ok');const field=document.getElementById('secCfgStrongConfirmation');if(field)field.value='';toast('Approved asset saved without network execution')}catch(e){if(await handleConflict(box,e))return;setState(box,'Rejected: '+e.message,'error');toast('Approved asset save blocked: '+e.message)}}\n"
    "async function disableAsset(box){const assetId=box.querySelector('.secAssetId').value.trim();if(!assetId){setState(box,'Asset ID is required','error');return}if(!configFingerprint){await loadFingerprint();if(!configFingerprint)return}setState(box,'Disabling exact asset…');try{const data=await jsonRequest('/api/security/assets/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset_id:assetId,expected_config_fingerprint:configFingerprint,confirmation:confirmation()})});configFingerprint=String(data.config_fingerprint||configFingerprint);box.querySelector('.secAssetEnabled').checked=false;setState(box,'disabled · network execution=false','ok');const field=document.getElementById('secCfgStrongConfirmation');if(field)field.value='';toast('Approved asset disabled; no network action was executed')}catch(e){if(await handleConflict(box,e))return;setState(box,'Rejected: '+e.message,'error');toast('Approved asset disable blocked: '+e.message)}}\n"
    "function decorate(box){if(box.dataset.exactAssetControls==='1')return;box.dataset.exactAssetControls='1';const head=box.querySelector('.security-asset-head');if(!head)return;const existing=head.querySelector('.secAssetRemove');if(existing)existing.textContent='Remove draft row';const actions=document.createElement('div');actions.className='security-asset-exact-actions';const save=document.createElement('button');save.type='button';save.className='soft-btn';save.textContent='Save asset';save.onclick=()=>saveAsset(box);const disable=document.createElement('button');disable.type='button';disable.className='soft-btn';disable.textContent='Disable asset';disable.onclick=()=>disableAsset(box);actions.append(save,disable);head.appendChild(actions);stateNode(box)}\n"
    "function decorateEditors(){for(const box of root.querySelectorAll('.security-asset-editor'))decorate(box)}\n"
    'new MutationObserver(decorateEditors).observe(root,{childList:true,subtree:true});\n'
    "configTab.addEventListener('click',()=>window.setTimeout(loadFingerprint,0));\n"
    "document.getElementById('secCfgReload')?.addEventListener('click',()=>window.setTimeout(loadFingerprint,80));\n"
    'decorateEditors();\n'
    '})();\n'
    '</script>\n'
    '</body>\n'
    '</html>'
)

html = WORKSPACE_HTML

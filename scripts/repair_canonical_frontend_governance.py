#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSOLIDATOR = ROOT / "scripts" / "consolidate_workspace_frontend.py"

ENTERPRISE_CSS = r'''
.security-change-control{margin-top:10px;border:1px solid #3a414b;background:#0e1115;border-radius:10px;padding:10px}.security-change-control h4{margin:0 0 8px;font-size:11px}.security-change-control textarea{width:100%;min-height:64px;resize:vertical;box-sizing:border-box;border:1px solid #363a42;background:#0b0d10;color:#e7e9ed;border-radius:8px;padding:8px 9px;font-size:11px}.security-governance-state{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin:8px 0}.security-governance-state .security-kv{padding:8px}.security-history{margin-top:9px;max-height:220px;overflow:auto;display:flex;flex-direction:column;gap:6px}.security-history-row{border:1px solid #30343b;border-radius:8px;padding:8px;background:#0d0f12;font-size:10px;line-height:1.45}.security-history-row b{display:block;color:#d8dbe1}.security-rollback-row{display:flex;gap:7px;align-items:flex-end;margin-top:8px}.security-rollback-row .security-config-field{flex:1}@media(max-width:640px){.security-governance-state{grid-template-columns:1fr}.security-rollback-row{align-items:stretch;flex-direction:column}}
'''

CHANGE_CONTROL_MARKUP = r'''
              <div class="security-change-control" id="secGovernancePanel">
                <h4>Enterprise change control</h4>
                <div class="security-config-help">Every production change requires a reason and the current revision. Stale saves, audit tampering and out-of-band drift are blocked.</div>
                <div class="security-governance-state" id="secGovernanceState"></div>
                <div class="security-config-field wide"><label>Change reason (required)</label><textarea id="secCfgChangeReason" maxlength="1200" placeholder="Ticket / incident / approved reason for this change"></textarea></div>
                <div class="security-config-actions">
                  <button class="soft-btn" id="secCfgHistory" type="button">History</button>
                  <button class="soft-btn" id="secCfgAdopt" type="button">Adopt existing</button>
                </div>
                <div class="security-rollback-row">
                  <div class="security-config-field"><label>Rollback source revision</label><input id="secCfgRollbackRevision" type="number" min="1" step="1" placeholder="e.g. 3"></div>
                  <button class="soft-btn" id="secCfgRollback" type="button">Rollback as new revision</button>
                </div>
                <div class="security-history" id="secCfgHistoryList"></div>
              </div>
'''

BASE_ACTIONS = '              <div class="security-config-actions">\n                <button class="soft-btn" id="secCfgReload" type="button">Reload</button>'

OLD_RENDER = "function renderEnvelope(d){loadedEnvelope=d;fill(d.config||{});meta.innerHTML='';metaKV('State',d.state);metaKV('Config path',d.config_path);metaKV('Path source',d.path_source);metaKV('Policy fingerprint',d.summary?.policy_fingerprint);setStatus(d.state==='configured'?'Configuration loaded.':'Safe defaults loaded but not saved.',true)}"
NEW_RENDER = r'''function renderGovernance(g={}){const box=document.getElementById('secGovernanceState');box.innerHTML='';const add=(k,v)=>{const el=document.createElement('div');el.className='security-kv';const b=document.createElement('b');b.textContent=k;const s=document.createElement('span');s.textContent=v===undefined||v===null?'—':String(v);el.append(b,s);box.appendChild(el)};add('Revision',g.revision??0);add('State',g.change_state||'unknown');add('Drift',g.drift_detected?'DETECTED':'No');add('Audit chain',g.audit_chain_valid===false?'INVALID':'Valid');const adopt=document.getElementById('secCfgAdopt');adopt.disabled=!g.adoption_required;document.getElementById('secCfgSave').disabled=g.change_state==='drift'||g.change_state==='audit_invalid'||g.adoption_required===true}
function renderEnvelope(d){loadedEnvelope=d;fill(d.config||{});meta.innerHTML='';metaKV('State',d.state);metaKV('Config path',d.config_path);metaKV('Path source',d.path_source);metaKV('Policy fingerprint',d.summary?.policy_fingerprint);renderGovernance(d.governance||{});const blocked=['drift','audit_invalid','adoption_required'].includes(d.governance?.change_state);setStatus(blocked?'CONFIGURATION GOVERNANCE BLOCKED: '+d.governance.change_state:(d.state==='configured'?'Configuration loaded.':'Safe defaults loaded but not saved.'),!blocked)}'''

OLD_SAVE = "async function saveConfig(){const payload=currentPayload();if(payload.policy.allow_active_liveness&&!confirm('Active liveness generates ICMP/TCP probe traffic to explicitly approved inventory only. Continue saving?'))return;if(payload.allow_real_network&&!confirm('Allow read-only network collection for explicitly approved assets? Saving does not start collection.'))return;try{setStatus('Validating and saving…');const d=await postConfig('/api/security/config/save',{config:payload});setStatus('SAVED\\nPolicy: '+d.summary.policy_fingerprint+'\\nReady: '+d.readiness.ready,true);await loadConfig();if(typeof refreshSecurityBadge==='function')refreshSecurityBadge()}catch(e){setStatus('SAVE BLOCKED\\n'+e.message,false)}}"
NEW_SAVE = r'''function changeReason(){return document.getElementById('secCfgChangeReason').value.trim()}
function currentRevision(){return Number(loadedEnvelope?.governance?.revision??0)}
async function saveConfig(){const payload=currentPayload(),reason=changeReason();if(!reason){setStatus('SAVE BLOCKED\nChange reason is required.',false);return}if(loadedEnvelope?.governance?.adoption_required){setStatus('SAVE BLOCKED\nAdopt the existing configuration before changing it.',false);return}if(payload.policy.allow_active_liveness&&!confirm('Active liveness generates ICMP/TCP probe traffic to explicitly approved inventory only. Continue saving?'))return;if(payload.allow_real_network&&!confirm('Allow read-only network collection for explicitly approved assets? Saving does not start collection.'))return;try{setStatus('Validating and saving governed revision…');const d=await postConfig('/api/security/config/save',{config:payload,expected_revision:currentRevision(),change_reason:reason});document.getElementById('secCfgChangeReason').value='';setStatus('SAVED REVISION '+d.revision+'\nPolicy: '+d.summary.policy_fingerprint+'\nReady: '+d.readiness.ready,true);await loadConfig();if(typeof refreshSecurityBadge==='function')refreshSecurityBadge()}catch(e){setStatus('SAVE BLOCKED\n'+e.message,false)}}
async function loadHistory(){try{const d=await api('/api/security/config/history?limit=50'),box=document.getElementById('secCfgHistoryList');box.innerHTML='';for(const item of d.history||[]){const row=document.createElement('div');row.className='security-history-row';const b=document.createElement('b');b.textContent='Revision '+item.revision+(item.source_revision?' · from '+item.source_revision:'');const s=document.createElement('span');s.textContent=(item.created_at||'')+' · '+(item.actor||'')+' · '+(item.reason||'');row.append(b,s);box.appendChild(row)}if(!(d.history||[]).length)box.textContent='No governed revisions yet.'}catch(e){setStatus('HISTORY FAILED\n'+e.message,false)}}
async function adoptExisting(){const reason=changeReason();if(!reason){setStatus('ADOPTION BLOCKED\nChange reason is required.',false);return}if(!confirm('Adopt the currently stored configuration as revision 1 after administrative review?'))return;try{const d=await postConfig('/api/security/config/adopt',{change_reason:reason});document.getElementById('secCfgChangeReason').value='';setStatus('ADOPTED REVISION '+d.revision,true);await loadConfig();await loadHistory()}catch(e){setStatus('ADOPTION BLOCKED\n'+e.message,false)}}
async function rollbackConfig(){const reason=changeReason(),source=Number(document.getElementById('secCfgRollbackRevision').value);if(!reason){setStatus('ROLLBACK BLOCKED\nChange reason is required.',false);return}if(!Number.isInteger(source)||source<1){setStatus('ROLLBACK BLOCKED\nChoose a valid source revision.',false);return}if(!confirm('Rollback from revision '+source+' by creating a new audited revision?'))return;try{const d=await postConfig('/api/security/config/rollback',{source_revision:source,expected_revision:currentRevision(),change_reason:reason});document.getElementById('secCfgChangeReason').value='';setStatus('ROLLBACK SAVED AS REVISION '+d.revision,true);await loadConfig();await loadHistory()}catch(e){setStatus('ROLLBACK BLOCKED\n'+e.message,false)}}'''

OLD_BINDINGS = "tab.onclick=openConfig;document.getElementById('secCfgAddAsset').onclick=()=>assets.appendChild(assetEditor());document.getElementById('secCfgReload').onclick=loadConfig;document.getElementById('secCfgValidate').onclick=validateConfig;document.getElementById('secCfgReadiness').onclick=readiness;document.getElementById('secCfgSave').onclick=saveConfig;document.getElementById('securityAnalystBtn').addEventListener('click',updateAccess);document.getElementById('loginBtn').addEventListener('click',()=>setTimeout(updateAccess,500));updateAccess();"
NEW_BINDINGS = "tab.onclick=openConfig;document.getElementById('secCfgAddAsset').onclick=()=>assets.appendChild(assetEditor());document.getElementById('secCfgReload').onclick=loadConfig;document.getElementById('secCfgValidate').onclick=validateConfig;document.getElementById('secCfgReadiness').onclick=readiness;document.getElementById('secCfgSave').onclick=saveConfig;document.getElementById('secCfgHistory').onclick=loadHistory;document.getElementById('secCfgAdopt').onclick=adoptExisting;document.getElementById('secCfgRollback').onclick=rollbackConfig;document.getElementById('securityAnalystBtn').addEventListener('click',updateAccess);document.getElementById('loginBtn').addEventListener('click',()=>setTimeout(updateAccess,500));updateAccess();"

REQUIRED_MARKERS = (
    "Enterprise change control",
    "Change reason (required)",
    "Rollback as new revision",
    "expected_revision",
    "/api/security/config/history",
    "/api/security/config/adopt",
    "/api/security/config/rollback",
    "CONFIGURATION GOVERNANCE BLOCKED",
)


def _load_consolidator():
    spec = importlib.util.spec_from_file_location("workspace_frontend_consolidator", CONSOLIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load workspace frontend consolidator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _replace_or_already(source: str, old: str, new: str, label: str) -> str:
    old_count = source.count(old)
    if old_count == 1:
        return source.replace(old, new, 1)
    new_count = source.count(new)
    if old_count == 0 and new_count == 1:
        return source
    raise RuntimeError(
        f"canonical governance repair '{label}' is ambiguous: old_count={old_count}, new_count={new_count}"
    )


def _repair(html: str) -> str:
    if ".security-change-control{" not in html:
        if html.count("</style>") != 1:
            raise RuntimeError("canonical governance CSS requires exactly one </style> boundary")
        html = html.replace("</style>", ENTERPRISE_CSS + "</style>", 1)

    if 'id="secGovernancePanel"' not in html:
        if html.count(BASE_ACTIONS) != 1:
            raise RuntimeError("canonical governance markup requires exactly one configuration action anchor")
        html = html.replace(BASE_ACTIONS, CHANGE_CONTROL_MARKUP + BASE_ACTIONS, 1)

    if "function renderGovernance(" not in html:
        html = _replace_or_already(html, OLD_RENDER, NEW_RENDER, "render-governance")
    if "function changeReason()" not in html:
        html = _replace_or_already(html, OLD_SAVE, NEW_SAVE, "governed-save")
    if "document.getElementById('secCfgHistory').onclick=loadHistory" not in html:
        html = _replace_or_already(html, OLD_BINDINGS, NEW_BINDINGS, "governance-bindings")

    missing = [marker for marker in REQUIRED_MARKERS if marker not in html]
    if missing:
        raise RuntimeError("canonical governance repair missing markers: " + ", ".join(missing))
    return html


def main() -> int:
    consolidator = _load_consolidator()
    html, config_markup, config_js = consolidator._load_canonical_authority()
    repaired = _repair(html)
    digest, changed = consolidator._write_canonical(repaired, config_markup, config_js)
    print(json.dumps({
        "status": "repaired" if changed else "noop",
        "final_html_sha256": digest,
        "rewritten_files": changed,
        "required_markers": list(REQUIRED_MARKERS),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

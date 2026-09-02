from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v17 import WORKSPACE_HTML_V17


html = WORKSPACE_HTML_V17

asset_css = r'''
.security-asset-exact-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-left:auto}.security-asset-exact-state{font-size:9px;color:#8d929c;max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.security-asset-exact-state.ok{color:#9ecfb3}.security-asset-exact-state.warn{color:#e3c895}.security-asset-exact-state.error{color:#e0a4a4}
'''
html = _replace_once(html, "</style>", asset_css + "</style>", "security-asset-onboarding-css")

asset_js = r'''
(function(){
const root=document.getElementById('secCfgAssets');
const configTab=document.getElementById('securityConfigTab');
if(!root||!configTab)return;
let configFingerprint='';
let snapshotLoading=false;
function toast(message){if(typeof window.showToast==='function')window.showToast(message)}
function confirmation(){const field=document.getElementById('secCfgStrongConfirmation');return field?field.value.trim():''}
async function jsonRequest(path,options={}){const response=await fetch(path,{credentials:'same-origin',...options});let data={};try{data=await response.json()}catch(e){}if(!response.ok){const error=new Error(data.error||data.code||('HTTP '+response.status));error.status=response.status;error.code=data.code||'';throw error}return data}
async function loadFingerprint(){if(snapshotLoading)return; snapshotLoading=true;try{const data=await jsonRequest('/api/security/assets/config');configFingerprint=String(data.config_fingerprint||'');decorateEditors()}catch(e){configFingerprint='';}finally{snapshotLoading=false}}
function assetFrom(box){return {asset_id:box.querySelector('.secAssetId').value.trim(),role:box.querySelector('.secAssetRole').value.trim(),management_host:box.querySelector('.secAssetHost').value.trim(),collector_capabilities:Array.from(box.querySelectorAll('.secAssetCaps input:checked')).map(x=>x.value),allowed_tcp_ports:box.querySelector('.secAssetPorts').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number),data_class:box.querySelector('.secAssetClass').value,enabled:box.querySelector('.secAssetEnabled').checked,credential_ref:box.querySelector('.secAssetCredential').value.trim()||null}}
function stateNode(box){let node=box.querySelector('.security-asset-exact-state');if(!node){node=document.createElement('span');node.className='security-asset-exact-state';const head=box.querySelector('.security-asset-head');if(head)head.appendChild(node)}return node}
function setState(box,message,kind=''){const node=stateNode(box);node.textContent=message;node.className='security-asset-exact-state'+(kind?' '+kind:'')}
async function handleConflict(box,error){if(error.status===409||error.code==='SECURITY_ASSET_CONFIG_STALE'){setState(box,'Stale configuration — reload before retry','warn');toast('Approved asset changed elsewhere. Reload Configuration before retry.');await loadFingerprint();const reload=document.getElementById('secCfgReload');if(reload)reload.click();return true}return false}
async function saveAsset(box){if(!configFingerprint){setState(box,'Load asset snapshot first','warn');await loadFingerprint();if(!configFingerprint)return}setState(box,'Saving exact asset…');try{const data=await jsonRequest('/api/security/assets/upsert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset:assetFrom(box),expected_config_fingerprint:configFingerprint,confirmation:confirmation()})});configFingerprint=String(data.config_fingerprint||configFingerprint);setState(box,(data.action||'saved')+' · network execution=false','ok');const field=document.getElementById('secCfgStrongConfirmation');if(field)field.value='';toast('Approved asset saved without network execution')}catch(e){if(await handleConflict(box,e))return;setState(box,'Rejected: '+e.message,'error');toast('Approved asset save blocked: '+e.message)}}
async function disableAsset(box){const assetId=box.querySelector('.secAssetId').value.trim();if(!assetId){setState(box,'Asset ID is required','error');return}if(!configFingerprint){await loadFingerprint();if(!configFingerprint)return}setState(box,'Disabling exact asset…');try{const data=await jsonRequest('/api/security/assets/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset_id:assetId,expected_config_fingerprint:configFingerprint,confirmation:confirmation()})});configFingerprint=String(data.config_fingerprint||configFingerprint);box.querySelector('.secAssetEnabled').checked=false;setState(box,'disabled · network execution=false','ok');const field=document.getElementById('secCfgStrongConfirmation');if(field)field.value='';toast('Approved asset disabled; no network action was executed')}catch(e){if(await handleConflict(box,e))return;setState(box,'Rejected: '+e.message,'error');toast('Approved asset disable blocked: '+e.message)}}
function decorate(box){if(box.dataset.exactAssetControls==='1')return;box.dataset.exactAssetControls='1';const head=box.querySelector('.security-asset-head');if(!head)return;const existing=head.querySelector('.secAssetRemove');if(existing)existing.textContent='Remove draft row';const actions=document.createElement('div');actions.className='security-asset-exact-actions';const save=document.createElement('button');save.type='button';save.className='soft-btn';save.textContent='Save asset';save.onclick=()=>saveAsset(box);const disable=document.createElement('button');disable.type='button';disable.className='soft-btn';disable.textContent='Disable asset';disable.onclick=()=>disableAsset(box);actions.append(save,disable);head.appendChild(actions);stateNode(box)}
function decorateEditors(){for(const box of root.querySelectorAll('.security-asset-editor'))decorate(box)}
new MutationObserver(decorateEditors).observe(root,{childList:true,subtree:true});
configTab.addEventListener('click',()=>window.setTimeout(loadFingerprint,0));
document.getElementById('secCfgReload')?.addEventListener('click',()=>window.setTimeout(loadFingerprint,80));
decorateEditors();
})();
'''
html = _replace_once(html, "</body>", "<script>" + asset_js + "</script>\n</body>", "security-asset-onboarding-js")

WORKSPACE_HTML_V18 = html

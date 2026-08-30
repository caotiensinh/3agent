from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v6 import WORKSPACE_HTML_V6

html = WORKSPACE_HTML_V6

external_css = r"""
.login-divider{display:flex;align-items:center;gap:10px;margin:14px 0;color:#767982;font-size:12px}.login-divider:before,.login-divider:after{content:'';height:1px;background:#34363d;flex:1}.external-login-list{display:grid;gap:8px}.external-login-btn{height:42px;display:flex!important;align-items:center;justify-content:center;gap:9px;background:#24262b!important;border:1px solid #41434a!important}.external-login-btn:hover{background:#2c2e34!important}.external-login-btn.hidden,.login-divider.hidden{display:none!important}.external-login-note{font-size:11px;color:#7f828a;margin-top:10px;line-height:1.4}.external-admin{border-top:1px solid #36383f;padding:12px 16px}.external-admin h3{font-size:13px;margin:0 0 8px}.external-identity-row{display:grid;grid-template-columns:110px minmax(130px,1fr) minmax(150px,1fr) auto;gap:8px;align-items:center;padding:9px 0;border-bottom:1px solid #2e3035}.external-provider{text-transform:capitalize;font-weight:650}.external-identity-row select{min-width:0;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:8px;padding:7px}.external-status{font-size:11px;color:var(--muted)}.external-actions{display:flex;gap:6px}.external-actions button{white-space:nowrap}@media(max-width:760px){.external-identity-row{grid-template-columns:1fr 1fr}.external-actions{grid-column:1/-1}}
"""
html = _replace_once(html, "</style>", external_css + "</style>", "external-auth-css")

login_button = '    <button class="soft-btn primary" id="loginBtn">Sign in</button>'
external_login = login_button + r'''
    <div class="login-divider hidden" id="externalLoginDivider"><span>or</span></div>
    <div class="external-login-list" id="externalLoginList"></div>
    <div class="external-login-note hidden" id="externalLoginNote">External providers verify identity only. WorkSpace data, projects and AI permissions remain local.</div>'''
html = _replace_once(html, login_button, external_login, "external-login-buttons")

user_list = '<div class="user-admin-users" id="userAdminUsers"></div>'
external_admin = user_list + r'''
    <div class="external-admin" id="externalIdentityAdmin">
      <h3>External login identities</h3>
      <div class="external-status">Google, GitHub and LINE identities must be explicitly bound to an existing local WorkSpace user.</div>
      <div id="externalIdentityList"></div>
    </div>'''
html = _replace_once(html, user_list, external_admin, "external-admin-ui")

external_js = r'''
state.authProviders={local:true,external:[],broker_url:''};
state.adminUsers=[];

function providerLabel(provider){return provider==='google'?'Google':provider==='github'?'GitHub':provider==='line'?'LINE':provider}
function providerButton(provider){const b=document.createElement('button');b.type='button';b.className='soft-btn external-login-btn';b.textContent='Continue with '+providerLabel(provider);b.onclick=()=>beginExternalLogin(provider);return b}
async function loadAuthProviders(){try{const d=await api('/api/auth/providers');state.authProviders=d;const list=document.getElementById('externalLoginList');list.innerHTML='';for(const provider of d.external||[])list.appendChild(providerButton(provider));const shown=(d.external||[]).length>0;document.getElementById('externalLoginDivider').classList.toggle('hidden',!shown);document.getElementById('externalLoginNote').classList.toggle('hidden',!shown)}catch(e){state.authProviders={local:true,external:[],broker_url:''}}}
function beginExternalLogin(provider){const d=state.authProviders||{};if(!(d.external||[]).includes(provider)||!d.broker_url){document.getElementById('loginErr').textContent='External login provider is not configured';return}const target=d.broker_url.replace(/\/$/,'')+'/auth/start/'+encodeURIComponent(provider)+'?return_to='+encodeURIComponent(window.location.origin);window.location.assign(target)}
async function completeExternalLoginFromFragment(){const raw=window.location.hash||'';const prefix='#workspace_external_ticket=';if(!raw.startsWith(prefix))return false;const ticket=decodeURIComponent(raw.slice(prefix.length));history.replaceState(null,'',window.location.pathname+window.location.search);try{const d=await api('/api/external/login',{method:'POST',body:JSON.stringify({ticket})});if(d.status==='pending'){document.getElementById('loginErr').textContent='Identity verified. An administrator must approve this account before first login.';return true}document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';await initializeWorkspace();return true}catch(e){document.getElementById('loginErr').textContent=e.message;return true}}
function externalIdentityRow(item){const row=document.createElement('div');row.className='external-identity-row';const provider=document.createElement('div');provider.className='external-provider';provider.textContent=providerLabel(item.provider);const info=document.createElement('div');const name=document.createElement('div');name.textContent=item.display_name||'Verified identity';const status=document.createElement('div');status.className='external-status';status.textContent=item.status;info.append(name,status);const select=document.createElement('select');const blank=document.createElement('option');blank.value='';blank.textContent='Select local user';select.appendChild(blank);for(const user of state.adminUsers||[]){if(!user.enabled)continue;const o=document.createElement('option');o.value=user.user_id;o.textContent=(user.display_name||user.username)+' (@'+user.username+')';if(item.user_id===user.user_id)o.selected=true;select.appendChild(o)}const actions=document.createElement('div');actions.className='external-actions';const approve=document.createElement('button');approve.type='button';approve.className='soft-btn';approve.textContent=item.status==='approved'?'Rebind':'Approve';approve.onclick=async()=>{if(!select.value){showToast('Select a local WorkSpace user first');return}try{await api('/api/external-identities/'+encodeURIComponent(item.identity_id)+'/approve',{method:'POST',body:JSON.stringify({user_id:select.value})});showToast('External identity approved');await loadExternalIdentities()}catch(e){showToast(e.message)}};const reject=document.createElement('button');reject.type='button';reject.className='soft-btn';reject.textContent='Reject';reject.onclick=async()=>{try{await api('/api/external-identities/'+encodeURIComponent(item.identity_id)+'/reject',{method:'POST',body:JSON.stringify({})});showToast('External identity rejected');await loadExternalIdentities()}catch(e){showToast(e.message)}};actions.append(approve,reject);row.append(provider,info,select,actions);return row}
async function loadExternalIdentities(){const wrap=document.getElementById('externalIdentityList');if(!wrap)return;try{const d=await api('/api/external-identities');wrap.innerHTML='';for(const item of d.identities||[])wrap.appendChild(externalIdentityRow(item));if(!(d.identities||[]).length){const empty=document.createElement('div');empty.className='library-empty';empty.textContent='No external identities have attempted login yet.';wrap.appendChild(empty)}}catch(e){wrap.innerHTML='';const empty=document.createElement('div');empty.className='library-empty';empty.textContent=e.message;wrap.appendChild(empty)}}
'''

html = _replace_once(
    html,
    "document.getElementById('sidebarToggle').onclick=toggleSidebar;",
    external_js + "\ndocument.getElementById('sidebarToggle').onclick=toggleSidebar;",
    "external-auth-js",
)

old_load_users = "async function loadUsers(){const wrap=document.getElementById('userAdminUsers');wrap.innerHTML='<div class=\"library-empty\">Loading users…</div>';try{const d=await api('/api/users');wrap.innerHTML='';for(const user of d.users||[])wrap.appendChild(userRow(user));if(!(d.users||[]).length)wrap.innerHTML='<div class=\"library-empty\">No users found.</div>'}catch(e){wrap.innerHTML='<div class=\"library-empty\"></div>';wrap.firstChild.textContent=e.message}}"
new_load_users = "async function loadUsers(){const wrap=document.getElementById('userAdminUsers');wrap.innerHTML='<div class=\"library-empty\">Loading users…</div>';try{const d=await api('/api/users');state.adminUsers=d.users||[];wrap.innerHTML='';for(const user of state.adminUsers)wrap.appendChild(userRow(user));if(!state.adminUsers.length)wrap.innerHTML='<div class=\"library-empty\">No users found.</div>'}catch(e){state.adminUsers=[];wrap.innerHTML='<div class=\"library-empty\"></div>';wrap.firstChild.textContent=e.message}}"
html = _replace_once(html, old_load_users, new_load_users, "external-admin-users")

old_open = "async function openUserAdmin(){closeAccountMenu();if(state.session?.role!=='admin'){showToast('Administrator role required');return}document.getElementById('userAdminModal').classList.add('open');await loadUsers()}"
new_open = "async function openUserAdmin(){closeAccountMenu();if(state.session?.role!=='admin'){showToast('Administrator role required');return}document.getElementById('userAdminModal').classList.add('open');await loadUsers();await loadExternalIdentities()}"
html = _replace_once(html, old_open, new_open, "external-admin-load")

old_bootstrap = "(async()=>{document.getElementById('username').value=localStorage.getItem('workspace.lastUsername')||'admin';try{await api('/api/session');document.getElementById('login').classList.add('hidden');await initializeWorkspace()}catch(e){}})();"
new_bootstrap = "(async()=>{document.getElementById('username').value=localStorage.getItem('workspace.lastUsername')||'admin';await loadAuthProviders();if(await completeExternalLoginFromFragment())return;try{await api('/api/session');document.getElementById('login').classList.add('hidden');await initializeWorkspace()}catch(e){}})();"
html = _replace_once(html, old_bootstrap, new_bootstrap, "external-auth-bootstrap")

WORKSPACE_HTML_V7 = html

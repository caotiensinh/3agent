from __future__ import annotations

from .workspace_frontend_v2 import WORKSPACE_HTML_V2


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"WorkSpace frontend v3 patch '{label}' expected exactly one match, got {count}"
        )
    return source.replace(old, new, 1)


html = WORKSPACE_HTML_V2

html = _replace_once(
    html,
    "#login{position:fixed;inset:0;background:#090a0c;z-index:50;display:flex;align-items:center;justify-content:center}.login-card{width:min(420px,90vw);background:#191a1e;border:1px solid #3b3d44;border-radius:20px;padding:25px;box-shadow:var(--shadow)}.login-card h2{margin:0 0 6px}.login-card p{color:var(--muted)}.login-card input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:11px;padding:11px 12px;margin:6px 0 12px;outline:0}.login-card button{width:100%}.login-error{color:var(--danger);font-size:12px}",
    "#login{position:fixed;inset:0;background:#090a0c;z-index:50;display:flex;align-items:center;justify-content:center}.login-card{width:min(420px,90vw);background:#191a1e;border:1px solid #3b3d44;border-radius:20px;padding:25px;box-shadow:var(--shadow)}.login-card h2{margin:0 0 6px}.login-card p{color:var(--muted)}.login-card input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:11px;padding:11px 12px;margin:6px 0 12px;outline:0}.login-card button{width:100%}.login-error{color:var(--danger);font-size:12px}.user-admin-card{width:min(820px,96vw);max-height:84vh}.user-admin-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;padding:14px 16px;border-bottom:1px solid #36383f}.user-admin-form input,.user-admin-form select,.password-form input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:9px;padding:9px 10px;outline:0}.user-admin-form .wide{grid-column:1/-1}.user-admin-users{overflow:auto;padding:8px 12px 14px}.user-admin-row{display:grid;grid-template-columns:minmax(150px,1.2fr) minmax(120px,1fr) 100px 82px auto;gap:8px;align-items:center;padding:10px;border-bottom:1px solid #2e3035}.user-admin-row input,.user-admin-row select{min-width:0;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:8px;padding:7px}.user-admin-name{font-weight:650;overflow:hidden;text-overflow:ellipsis}.user-admin-meta{font-size:11px;color:var(--muted)}.password-form{display:grid;gap:10px;padding:16px}@media(max-width:760px){.user-admin-form{grid-template-columns:1fr}.user-admin-form .wide{grid-column:auto}.user-admin-row{grid-template-columns:1fr 92px}.user-admin-row .user-admin-profile{grid-column:1/-1}}",
    "account-css",
)

html = _replace_once(
    html,
    "    <p>Enter the LAN access key.</p>\n    <input id=\"key\" type=\"password\" autocomplete=\"current-password\" placeholder=\"Access key\">\n    <button class=\"soft-btn primary\" id=\"loginBtn\">Connect</button>",
    "    <p>Sign in to your local WorkSpace account.</p>\n    <input id=\"username\" type=\"text\" autocomplete=\"username\" placeholder=\"Username\">\n    <input id=\"key\" type=\"password\" autocomplete=\"current-password\" placeholder=\"Password\">\n    <button class=\"soft-btn primary\" id=\"loginBtn\">Sign in</button>",
    "login-form",
)

html = _replace_once(
    html,
    "    <div class=\"account-menu\" id=\"accountMenu\">\n      <button type=\"button\" id=\"logoutBtn\">Log out</button>\n    </div>",
    "    <div class=\"account-menu\" id=\"accountMenu\">\n      <button type=\"button\" id=\"manageUsersBtn\" class=\"hidden\">Manage users</button>\n      <button type=\"button\" id=\"changePasswordBtn\">Change password</button>\n      <button type=\"button\" id=\"logoutBtn\">Log out</button>\n    </div>",
    "account-menu",
)

modals = r'''
<div class="library-modal" id="userAdminModal">
  <div class="library-card user-admin-card">
    <div class="library-head"><h2>WorkSpace users</h2><button class="soft-btn" id="closeUserAdmin" type="button">Close</button></div>
    <form class="user-admin-form" id="createUserForm">
      <input id="newUsername" autocomplete="off" placeholder="Username" required>
      <input id="newDisplayName" autocomplete="off" placeholder="Display name" required>
      <input id="newDepartment" autocomplete="off" placeholder="Department">
      <input id="newTitle" autocomplete="off" placeholder="Job title">
      <select id="newRole"><option value="user">User</option><option value="admin">Admin</option></select>
      <input id="newUserPassword" type="password" autocomplete="new-password" placeholder="Temporary password (16+ chars)" required>
      <button class="soft-btn primary wide" type="submit">Create account</button>
    </form>
    <div class="user-admin-users" id="userAdminUsers"></div>
  </div>
</div>
<div class="library-modal" id="passwordModal">
  <div class="library-card" style="width:min(460px,96vw)">
    <div class="library-head"><h2>Change password</h2><button class="soft-btn" id="closePasswordModal" type="button">Close</button></div>
    <form class="password-form" id="passwordForm">
      <input id="currentPassword" type="password" autocomplete="current-password" placeholder="Current password" required>
      <input id="newPassword" type="password" autocomplete="new-password" placeholder="New password (16+ chars)" required>
      <input id="confirmPassword" type="password" autocomplete="new-password" placeholder="Confirm new password" required>
      <button class="soft-btn primary" type="submit">Change password</button>
    </form>
  </div>
</div>
'''
html = _replace_once(
    html,
    '<div class="library-modal" id="libraryModal">',
    modals + '<div class="library-modal" id="libraryModal">',
    "account-modals",
)

html = _replace_once(
    html,
    "async function loadSession(){const d=await api('/api/session');state.session=d;document.getElementById('accountName').textContent=d.display_name||'WorkSpace User';document.getElementById('accountSub').textContent=d.subtitle||'Local LAN session';document.getElementById('accountAvatar').textContent=d.initials||'W'}",
    "async function loadSession(){const d=await api('/api/session');state.session=d;document.getElementById('accountName').textContent=d.display_name||d.username||'WorkSpace User';document.getElementById('accountSub').textContent=d.subtitle||d.department||'WorkSpace user';document.getElementById('accountAvatar').textContent=d.initials||'W';document.getElementById('manageUsersBtn').classList.toggle('hidden',d.role!=='admin')}",
    "session-ui",
)

account_js = r'''
function closeAccountMenu(){document.getElementById('accountMenu').classList.remove('open')}
function closeUserAdmin(){document.getElementById('userAdminModal').classList.remove('open')}
function closePasswordModal(){document.getElementById('passwordModal').classList.remove('open')}
function userRow(user){const row=document.createElement('div');row.className='user-admin-row';const profile=document.createElement('div');profile.className='user-admin-profile';const name=document.createElement('div');name.className='user-admin-name';name.textContent=user.display_name||user.username;const meta=document.createElement('div');meta.className='user-admin-meta';meta.textContent='@'+user.username+(user.department?' · '+user.department:'');profile.append(name,meta);const display=document.createElement('input');display.value=user.display_name||'';display.placeholder='Display name';const role=document.createElement('select');role.innerHTML='<option value="user">User</option><option value="admin">Admin</option>';role.value=user.role;const enabled=document.createElement('label');enabled.className='user-admin-meta';const check=document.createElement('input');check.type='checkbox';check.checked=!!user.enabled;enabled.append(check,document.createTextNode(' Enabled'));const save=document.createElement('button');save.type='button';save.className='soft-btn';save.textContent='Save';save.onclick=async()=>{try{await api('/api/users/'+encodeURIComponent(user.user_id),{method:'POST',body:JSON.stringify({display_name:display.value,role:role.value,enabled:check.checked})});showToast('User updated');await loadUsers();await loadSession()}catch(e){showToast(e.message)}};row.append(profile,display,role,enabled,save);return row}
async function loadUsers(){const wrap=document.getElementById('userAdminUsers');wrap.innerHTML='<div class="library-empty">Loading users…</div>';try{const d=await api('/api/users');wrap.innerHTML='';for(const user of d.users||[])wrap.appendChild(userRow(user));if(!(d.users||[]).length)wrap.innerHTML='<div class="library-empty">No users found.</div>'}catch(e){wrap.innerHTML='<div class="library-empty"></div>';wrap.firstChild.textContent=e.message}}
async function openUserAdmin(){closeAccountMenu();if(state.session?.role!=='admin'){showToast('Administrator role required');return}document.getElementById('userAdminModal').classList.add('open');await loadUsers()}
async function createUser(e){e.preventDefault();try{await api('/api/users',{method:'POST',body:JSON.stringify({username:document.getElementById('newUsername').value,display_name:document.getElementById('newDisplayName').value,department:document.getElementById('newDepartment').value,title:document.getElementById('newTitle').value,role:document.getElementById('newRole').value,password:document.getElementById('newUserPassword').value})});e.target.reset();showToast('Account created');await loadUsers()}catch(err){showToast(err.message)}}
async function changePassword(e){e.preventDefault();const next=document.getElementById('newPassword').value,confirm=document.getElementById('confirmPassword').value;if(next!==confirm){showToast('New passwords do not match');return}try{await api('/api/account/password',{method:'POST',body:JSON.stringify({current_password:document.getElementById('currentPassword').value,new_password:next})});closePasswordModal();document.getElementById('passwordForm').reset();state.currentConversationId=null;state.conversations=[];document.getElementById('login').classList.remove('hidden');document.getElementById('key').value='';showEmpty();showToast('Password changed. Sign in again.')}catch(err){showToast(err.message)}}
'''

html = _replace_once(
    html,
    "async function login(){const key=document.getElementById('key').value;try{await api('/api/login',{method:'POST',body:JSON.stringify({token:key})});document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';await initializeWorkspace()}catch(e){document.getElementById('loginErr').textContent=e.message}}\nasync function logout(){try{await api('/api/logout',{method:'POST',body:JSON.stringify({})})}catch(e){}state.currentConversationId=null;state.conversations=[];document.getElementById('accountMenu').classList.remove('open');document.getElementById('login').classList.remove('hidden');document.getElementById('key').value='';showEmpty()}",
    "async function login(){const username=document.getElementById('username').value.trim(),key=document.getElementById('key').value;try{const d=await api('/api/login',{method:'POST',body:JSON.stringify({username:username,password:key})});localStorage.setItem('workspace.lastUsername',username);document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';if(d.legacy_history_migrated)showToast('Legacy local history migrated to this account');await initializeWorkspace()}catch(e){document.getElementById('loginErr').textContent=e.message}}\nasync function logout(){try{await api('/api/logout',{method:'POST',body:JSON.stringify({})})}catch(e){}state.currentConversationId=null;state.conversations=[];closeAccountMenu();document.getElementById('login').classList.remove('hidden');document.getElementById('key').value='';showEmpty()}\n" + account_js,
    "account-js",
)

html = _replace_once(
    html,
    "document.getElementById('accountBtn').onclick=()=>document.getElementById('accountMenu').classList.toggle('open');\ndocument.getElementById('logoutBtn').onclick=logout;\ndocument.getElementById('loginBtn').onclick=login;\ndocument.getElementById('key').addEventListener('keydown',e=>{if(e.key==='Enter')login()});",
    "document.getElementById('accountBtn').onclick=()=>document.getElementById('accountMenu').classList.toggle('open');\ndocument.getElementById('manageUsersBtn').onclick=openUserAdmin;\ndocument.getElementById('changePasswordBtn').onclick=()=>{closeAccountMenu();document.getElementById('passwordModal').classList.add('open');document.getElementById('currentPassword').focus()};\ndocument.getElementById('logoutBtn').onclick=logout;\ndocument.getElementById('loginBtn').onclick=login;\ndocument.getElementById('key').addEventListener('keydown',e=>{if(e.key==='Enter')login()});\ndocument.getElementById('username').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('key').focus()});\ndocument.getElementById('closeUserAdmin').onclick=closeUserAdmin;\ndocument.getElementById('closePasswordModal').onclick=closePasswordModal;\ndocument.getElementById('createUserForm').addEventListener('submit',createUser);\ndocument.getElementById('passwordForm').addEventListener('submit',changePassword);",
    "account-events",
)

html = _replace_once(
    html,
    "(async()=>{try{await api('/api/session');document.getElementById('login').classList.add('hidden');await initializeWorkspace()}catch(e){}})();",
    "(async()=>{document.getElementById('username').value=localStorage.getItem('workspace.lastUsername')||'admin';try{await api('/api/session');document.getElementById('login').classList.add('hidden');await initializeWorkspace()}catch(e){}})();",
    "login-bootstrap",
)

WORKSPACE_HTML_V3 = html

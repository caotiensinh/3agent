from __future__ import annotations

WORKSPACE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WorkSpace</title>
<style>
:root{
  color-scheme:dark;
  --bg:#08090b;--panel:#17181b;--panel2:#202124;--panel3:#292a2e;
  --line:#33353b;--line2:#444750;--text:#f2f3f5;--muted:#a6a8ad;
  --accent:#5b7cfa;--accent2:#7894ff;--danger:#ff9696;--ok:#75d49a;
  --shadow:0 18px 55px rgba(0,0,0,.42)
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:radial-gradient(circle at 50% 18%,#11131a 0,#090a0d 34%,#07080a 72%);color:var(--text);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow:hidden}
button,select,textarea,input{font:inherit}
button{color:inherit}
.hidden{display:none!important}
.shell{height:100vh;display:flex;flex-direction:column}
.topbar{height:72px;display:grid;grid-template-columns:1fr auto 1fr;align-items:center;padding:0 28px;flex:0 0 auto}
.top-left,.top-right{display:flex;align-items:center;gap:8px}.top-right{justify-content:flex-end}
.brand{display:flex;align-items:center;gap:10px;font-size:19px;font-weight:700;letter-spacing:-.02em}
.brand-mark{width:28px;height:28px;border:2px solid var(--accent2);border-radius:8px;display:grid;place-items:center;transform:rotate(30deg);box-shadow:0 0 24px rgba(91,124,250,.24)}
.brand-mark::after{content:"";width:9px;height:9px;border:2px solid #8d6bff;border-radius:3px}
.icon-btn{width:40px;height:40px;border:0;background:transparent;border-radius:12px;display:grid;place-items:center;cursor:pointer}
.icon-btn:hover{background:#1b1d21}.icon-btn svg{width:21px;height:21px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.avatar{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:#202449;border:1px solid #4950a2;position:relative;font-weight:650}
.avatar::after{content:"";position:absolute;right:-1px;bottom:1px;width:9px;height:9px;border-radius:50%;background:#4bd384;border:2px solid var(--bg)}
#messages{flex:1;overflow:auto;padding:24px 18px 230px;scrollbar-width:thin;scrollbar-color:#34363c transparent}
.empty-state{height:62vh;display:flex;align-items:center;justify-content:center;color:#777a81;text-align:center}
.msg{max-width:900px;margin:0 auto 24px;word-break:break-word}
.who{font-size:12px;color:var(--muted);margin:0 0 6px 4px}
.bubble{padding:17px 19px;border:1px solid var(--line);border-radius:18px;background:rgba(24,25,29,.92)}
.user .bubble{background:#202226;white-space:pre-wrap;margin-left:auto;max-width:80%}
.error .bubble{border-color:#784b50;color:#ffd0d0}
.report h1{font-size:24px;margin:0 0 14px}.report h2{font-size:17px;margin:22px 0 8px}.report p{margin:7px 0}.report ul{padding-left:22px}.report li{margin:5px 0}.report blockquote{margin:10px 0;padding:9px 12px;border-left:3px solid var(--accent);background:#171b27;color:#dce3ff}.report hr{border:0;border-top:1px solid var(--line);margin:20px 0}
.stages{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px}
.stage{border:1px solid var(--line);border-radius:12px;padding:9px 10px;font-size:12px;background:#111216}.stage b{display:block}.stage small{color:var(--muted)}.stage.completed{border-color:#386249}.stage.running{border-color:#4c5d97}.stage.blocked,.stage.failed{border-color:#75474c}.stage.skipped{opacity:.55}
.answerTools,.downloads{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.answerTools button,.downloads a,.tech a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:#24262b;border-radius:9px;padding:6px 10px;font-size:12px}
.downloads a.primaryFile{background:#e8e9ed;color:#111216;border-color:#e8e9ed;font-weight:700}
.tech{margin-top:10px;border:1px solid var(--line);border-radius:10px;padding:8px 10px;color:var(--muted)}.tech summary{cursor:pointer}.tech a{display:inline-block;margin:7px 7px 2px 0}
.composer-wrap{position:fixed;left:0;right:0;bottom:0;padding:48px 18px 22px;background:linear-gradient(transparent,rgba(8,9,11,.94) 24%,var(--bg) 54%);z-index:3;pointer-events:none}
.composer-area{max-width:940px;margin:auto;position:relative;pointer-events:auto}
.disclaimer{text-align:center;color:#7d8087;font-size:12px;margin-bottom:12px}
.composer{border:1px solid var(--line2);background:rgba(31,32,36,.96);border-radius:32px;box-shadow:0 14px 42px rgba(0,0,0,.28);display:flex;align-items:flex-end;gap:8px;padding:9px 10px 9px 10px;min-height:64px}
.circle-btn{width:46px;height:46px;border:1px solid #44474e;border-radius:50%;background:#242529;display:grid;place-items:center;cursor:pointer;flex:0 0 auto}
.circle-btn:hover{background:#2b2d32}.circle-btn svg{width:23px;height:23px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
#input{flex:1;border:0;background:transparent;color:var(--text);outline:0;resize:none;min-height:46px;max-height:170px;padding:11px 6px 8px;line-height:1.55}
#input::placeholder{color:#a5a7ad}
.composer-actions{display:flex;align-items:center;gap:5px;padding-bottom:0}
.effort-select{appearance:none;border:0;background:transparent;color:#d7d8dc;padding:12px 28px 12px 10px;outline:0;cursor:pointer;background-image:linear-gradient(45deg,transparent 50%,#aaa 50%),linear-gradient(135deg,#aaa 50%,transparent 50%);background-position:calc(100% - 14px) 19px,calc(100% - 9px) 19px;background-size:5px 5px,5px 5px;background-repeat:no-repeat}
.vline{width:1px;height:32px;background:#383a40;margin:0 3px}
#sendBtn{background:var(--accent);border-color:var(--accent);color:#fff}#sendBtn:hover{background:#6c88ff}#sendBtn:disabled{opacity:.45;cursor:not-allowed}
#micBtn[aria-disabled="true"]{color:#a6a8ad}
.mode-pill{position:absolute;left:68px;bottom:72px;display:none;align-items:center;gap:8px;border:1px solid #3b4262;background:#1a1d28;border-radius:999px;padding:6px 10px;color:#cfd8ff;font-size:12px}
.mode-pill.visible{display:flex}.mode-pill button{border:0;background:transparent;color:#aab8ef;cursor:pointer;padding:0}
.attachments{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 9px 10px}
.chip{display:flex;align-items:center;gap:6px;max-width:260px;border:1px solid #3a3d45;background:#1c1e22;border-radius:10px;padding:6px 8px;color:#d9dadd;font-size:12px}
.chip span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.chip button{border:0;background:transparent;color:#8f9299;padding:0 2px;cursor:pointer}
.plus-menu{position:absolute;left:0;bottom:76px;width:min(430px,calc(100vw - 36px));background:rgba(32,33,36,.98);border:1px solid #45474d;border-radius:22px;padding:8px;box-shadow:var(--shadow);display:none;z-index:8;overflow:hidden}
.plus-menu.open{display:block}
.menu-row{width:100%;border:0;background:transparent;color:var(--text);display:grid;grid-template-columns:42px 1fr auto;gap:8px;align-items:center;text-align:left;padding:11px 12px;border-radius:14px;cursor:pointer}
.menu-row:hover{background:#2a2b2f}.menu-row.disabled{opacity:.45;cursor:default}.menu-row.disabled:hover{background:transparent}.menu-icon{width:30px;height:30px;display:grid;place-items:center;color:#8ba0ff}.menu-icon.green{color:#69d7a5}.menu-icon.blue{color:#5cb4ff}.menu-icon.purple{color:#9c83ff}.menu-icon.white{color:#e5e5e7}.menu-icon svg{width:24px;height:24px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.menu-title{font-size:14px}.menu-sub{font-size:12px;color:#a1a4aa;margin-top:1px}.menu-state{font-size:11px;color:#9fa3ac}
.menu-divider{height:1px;background:#3a3c42;margin:5px 10px}
.menu-options{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:8px 10px 10px}.menu-options label{font-size:11px;color:#90939a;display:block}.menu-options select{width:100%;margin-top:4px;background:#292b30;color:#e7e8ea;border:1px solid #41444c;border-radius:9px;padding:7px}
.library-modal{position:fixed;inset:0;background:rgba(0,0,0,.58);z-index:10;display:none;align-items:center;justify-content:center;padding:20px}.library-modal.open{display:flex}
.library-card{width:min(680px,96vw);max-height:76vh;display:flex;flex-direction:column;background:#1b1c20;border:1px solid #44474f;border-radius:20px;box-shadow:var(--shadow)}
.library-head{display:flex;align-items:center;padding:16px 18px;border-bottom:1px solid #36383f}.library-head h2{font-size:17px;margin:0}.library-head button{margin-left:auto}
.library-list{overflow:auto;padding:8px}.library-empty{padding:30px;color:var(--muted);text-align:center}
.library-item{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:10px;border-radius:12px}.library-item:hover{background:#24262b}.library-item input{width:16px;height:16px}.library-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.library-meta{font-size:11px;color:#92959c}.library-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 16px;border-top:1px solid #36383f}
.soft-btn{border:1px solid #41444b;background:#26282d;border-radius:10px;padding:8px 12px;cursor:pointer}.soft-btn.primary{background:#e8e9ed;color:#111;border-color:#e8e9ed;font-weight:650}
.toast{position:fixed;left:50%;bottom:122px;transform:translateX(-50%);background:#292b30;border:1px solid #484b53;border-radius:12px;padding:9px 13px;color:#e5e6e9;font-size:12px;z-index:20;box-shadow:var(--shadow);opacity:0;pointer-events:none;transition:.18s}.toast.show{opacity:1}
#login{position:fixed;inset:0;background:#090a0c;z-index:30;display:flex;align-items:center;justify-content:center}
.login-card{width:min(420px,90vw);background:#191a1e;border:1px solid #3b3d44;border-radius:20px;padding:25px;box-shadow:var(--shadow)}.login-card h2{margin:0 0 6px}.login-card p{color:var(--muted)}.login-card input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:11px;padding:11px 12px;margin:6px 0 12px;outline:0}.login-card button{width:100%}.login-error{color:var(--danger);font-size:12px}
@media(max-width:720px){.topbar{padding:0 14px}.top-left{display:none}.brand{grid-column:2}.top-right{grid-column:3}.stages{grid-template-columns:1fr}.composer-wrap{padding-left:10px;padding-right:10px}.effort-select{max-width:88px}.user .bubble{max-width:92%}.menu-options{grid-template-columns:1fr}}
</style>
</head>
<body>
<div id="login">
  <div class="login-card">
    <h2>WorkSpace</h2>
    <p>Enter the LAN access key.</p>
    <input id="key" type="password" autocomplete="current-password" placeholder="Access key">
    <button class="soft-btn primary" id="loginBtn">Connect</button>
    <div id="loginErr" class="login-error"></div>
  </div>
</div>

<div class="shell">
  <header class="topbar">
    <div class="top-left">
      <button class="icon-btn" type="button" aria-label="Recent conversations" id="recentBtn">
        <svg viewBox="0 0 24 24"><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3h8A2.5 2.5 0 0 1 17 5.5v8a2.5 2.5 0 0 1-2.5 2.5h-8A2.5 2.5 0 0 1 4 13.5z"/><path d="M8 7h9.5A2.5 2.5 0 0 1 20 9.5v8a2.5 2.5 0 0 1-2.5 2.5h-8A2.5 2.5 0 0 1 7 17.5V16"/></svg>
      </button>
      <button class="icon-btn" type="button" aria-label="Clear local view" id="clearBtn">
        <svg viewBox="0 0 24 24"><path d="M4 4v6h6"/><path d="M5.5 9A8 8 0 1 1 6 17"/></svg>
      </button>
    </div>
    <div class="brand"><span class="brand-mark" aria-hidden="true"></span><span id="brandText">WorkSpace</span></div>
    <div class="top-right"><div class="avatar" aria-label="WorkSpace session">W</div></div>
  </header>

  <main id="messages">
    <div class="empty-state" id="emptyState">Your local WorkSpace conversation will appear here.</div>
  </main>
</div>

<div class="composer-wrap">
  <div class="composer-area">
    <div class="disclaimer">WorkSpace may make mistakes. Check important info.</div>
    <div id="attachments" class="attachments"></div>
    <div id="modePill" class="mode-pill"><span id="modeLabel"></span><button type="button" id="clearModeBtn" aria-label="Clear mode">×</button></div>

    <div id="plusMenu" class="plus-menu" role="menu" aria-label="WorkSpace tools">
      <button class="menu-row" type="button" data-action="upload" role="menuitem">
        <span class="menu-icon purple"><svg viewBox="0 0 24 24"><path d="M8.5 12.5v-6a3.5 3.5 0 0 1 7 0v9a5 5 0 0 1-10 0v-9"/><path d="M11 7v8.5a2 2 0 0 0 4 0V8"/></svg></span>
        <span><div class="menu-title">Add photos &amp; files</div><div class="menu-sub">Upload from this computer</div></span><span class="menu-state"></span>
      </button>
      <button class="menu-row" type="button" data-action="library" role="menuitem">
        <span class="menu-icon green"><svg viewBox="0 0 24 24"><path d="M4 5v14M9 5v14M14 5l4 14M4 7h5M4 17h5"/></svg></span>
        <span><div class="menu-title">Add from library</div><div class="menu-sub">Reuse your previously validated uploads</div></span><span class="menu-state"></span>
      </button>
      <button class="menu-row" type="button" data-action="image_generation" role="menuitem">
        <span class="menu-icon blue"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3"/><circle cx="9" cy="9" r="1.5"/><path d="m5 17 4-4 3 3 2-2 5 4"/></svg></span>
        <span><div class="menu-title">Create image</div><div class="menu-sub">Local image generation</div></span><span class="menu-state"></span>
      </button>
      <button class="menu-row" type="button" data-action="web_search" role="menuitem">
        <span class="menu-icon blue"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg></span>
        <span><div class="menu-title">Web search</div><div class="menu-sub">Use policy-authorized public research only</div></span><span class="menu-state"></span>
      </button>
      <button class="menu-row" type="button" data-action="deep_research" role="menuitem">
        <span class="menu-icon purple"><svg viewBox="0 0 24 24"><path d="m4 18 7-7"/><path d="m9 9 6-3 3 3-3 6-6-6Z"/><path d="M14 5l2-2M18 7l3-1M17 11l2 2"/></svg></span>
        <span><div class="menu-title">Deep research</div><div class="menu-sub">Thorough evidence-bounded WorkSpace workflow</div></span><span class="menu-state"></span>
      </button>
      <button class="menu-row" type="button" data-action="github" role="menuitem">
        <span class="menu-icon white"><svg viewBox="0 0 24 24"><path d="M9 19c-4 1.2-4-2-5-2.5M14 21v-3.2c0-.9.3-1.6.8-2.1 2.7-.3 5.5-1.3 5.5-6A4.7 4.7 0 0 0 19 6.3 4.4 4.4 0 0 0 18.9 3S17.8 2.7 15 4.3a11.4 11.4 0 0 0-6 0C6.2 2.7 5.1 3 5.1 3A4.4 4.4 0 0 0 5 6.3a4.7 4.7 0 0 0-1.3 3.4c0 4.7 2.8 5.7 5.5 6 .5.5.8 1.2.8 2.1V21"/></svg></span>
        <span><div class="menu-title">GitHub</div><div class="menu-sub">Repository actions remain operator-controlled</div></span><span class="menu-state"></span>
      </button>
      <div class="menu-divider"></div>
      <div class="menu-options">
        <label>Language<select id="lang"><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>
        <label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + PDF</option><option value="all">Report + PPTX + PDF</option></select></label>
      </div>
    </div>

    <div class="composer">
      <button class="circle-btn" type="button" id="plusBtn" aria-label="Add files and tools" aria-expanded="false">
        <svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>
      </button>
      <input id="fileInput" type="file" multiple hidden accept=".txt,.md,.markdown,.html,.htm,.zip,.png,.jpg,.jpeg,.webp,text/plain,text/markdown,text/html,application/zip,image/png,image/jpeg,image/webp">
      <textarea id="input" rows="1" maxlength="12000" placeholder="Ask WorkSpace"></textarea>
      <div class="composer-actions">
        <select id="effort" class="effort-select" aria-label="Response effort"><option value="standard">Standard</option><option value="high" selected>High</option></select>
        <div class="vline"></div>
        <button class="icon-btn" type="button" id="micBtn" aria-label="Voice input" aria-disabled="true">
          <svg viewBox="0 0 24 24"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.5 11.5a6.5 6.5 0 0 0 13 0M12 18v3M9 21h6"/></svg>
        </button>
        <button class="circle-btn" type="button" id="sendBtn" aria-label="Send message">
          <svg viewBox="0 0 24 24"><path d="M12 19V5M6.5 10.5 12 5l5.5 5.5"/></svg>
        </button>
      </div>
    </div>
  </div>
</div>

<div id="libraryModal" class="library-modal" role="dialog" aria-modal="true" aria-labelledby="libraryTitle">
  <div class="library-card">
    <div class="library-head"><h2 id="libraryTitle">WorkSpace library</h2><button class="icon-btn" type="button" id="libraryClose" aria-label="Close">×</button></div>
    <div id="libraryList" class="library-list"></div>
    <div class="library-foot"><button class="soft-btn" type="button" id="libraryCancel">Cancel</button><button class="soft-btn primary" type="button" id="libraryApply">Add selected</button></div>
  </div>
</div>
<div id="toast" class="toast" role="status" aria-live="polite"></div>

<script>
const messages=document.getElementById('messages');
const input=document.getElementById('input');
const plusMenu=document.getElementById('plusMenu');
const plusBtn=document.getElementById('plusBtn');
const fileInput=document.getElementById('fileInput');
const attachmentsEl=document.getElementById('attachments');
const toastEl=document.getElementById('toast');
const libraryModal=document.getElementById('libraryModal');
const libraryList=document.getElementById('libraryList');
const sendBtn=document.getElementById('sendBtn');
const state={capabilities:null,selectedFiles:[],selectedUploads:[],requestMode:'chat',libraryDraft:new Set()};
let toastTimer=null;

function showToast(text){toastEl.textContent=String(text||'');toastEl.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>toastEl.classList.remove('show'),2800)}
function feature(name){return state.capabilities?.features?.[name]||{enabled:false,reason:'Capability information is unavailable.'}}
function closeMenu(){plusMenu.classList.remove('open');plusBtn.setAttribute('aria-expanded','false')}
function toggleMenu(){const next=!plusMenu.classList.contains('open');plusMenu.classList.toggle('open',next);plusBtn.setAttribute('aria-expanded',String(next))}
function updateInputHeight(){input.style.height='auto';input.style.height=Math.min(input.scrollHeight,170)+'px'}
function setMode(mode){
  state.requestMode=mode;
  const pill=document.getElementById('modePill'),label=document.getElementById('modeLabel');
  const labels={web_search:'Web search',deep_research:'Deep research'};
  if(labels[mode]){label.textContent=labels[mode];pill.classList.add('visible')}else{pill.classList.remove('visible')}
}
function renderCapabilities(){
  const cap=state.capabilities;if(!cap)return;
  document.getElementById('brandText').textContent=cap.product_name||'WorkSpace';
  for(const row of plusMenu.querySelectorAll('[data-action]')){
    const f=feature(row.dataset.action);row.classList.toggle('disabled',!f.enabled);
    row.querySelector('.menu-state').textContent=f.enabled?'':(f.state_label||'Unavailable');
    row.title=f.enabled?'':(f.reason||'Unavailable');
  }
  const mic=feature('voice_input'),micBtn=document.getElementById('micBtn');
  micBtn.setAttribute('aria-disabled',String(!mic.enabled));micBtn.title=mic.enabled?'Voice input':(mic.reason||'Voice input unavailable');
}
function renderAttachments(){
  attachmentsEl.innerHTML='';
  state.selectedFiles.forEach((f,i)=>{
    const chip=document.createElement('div');chip.className='chip';
    const name=document.createElement('span');name.textContent=f.name;
    const x=document.createElement('button');x.type='button';x.textContent='×';x.ariaLabel='Remove '+f.name;x.onclick=()=>{state.selectedFiles.splice(i,1);renderAttachments()};
    chip.append(name,x);attachmentsEl.appendChild(chip);
  });
  state.selectedUploads.forEach((u,i)=>{
    const chip=document.createElement('div');chip.className='chip';
    const name=document.createElement('span');name.textContent='Library · '+u.name;
    const x=document.createElement('button');x.type='button';x.textContent='×';x.ariaLabel='Remove '+u.name;x.onclick=()=>{state.selectedUploads.splice(i,1);renderAttachments()};
    chip.append(name,x);attachmentsEl.appendChild(chip);
  });
}
function appendInline(el,text){
  const re=/(https?:\/\/[^\s]+)/g;let pos=0;
  for(const m of String(text||'').matchAll(re)){
    el.appendChild(document.createTextNode(text.slice(pos,m.index)));
    const a=document.createElement('a');a.href=m[0];a.target='_blank';a.rel='noopener noreferrer';a.textContent=m[0];a.style.color='var(--accent2)';el.appendChild(a);
    pos=m.index+m[0].length;
  }
  el.appendChild(document.createTextNode(String(text||'').slice(pos)));
}
function renderReport(text){
  const root=document.createElement('div');root.className='report';let list=null;
  for(const raw of String(text||'').split('\n')){
    const line=raw.trimEnd();if(!line.trim()){list=null;continue}
    if(line==='---'){root.appendChild(document.createElement('hr'));list=null;continue}
    const h=line.match(/^(#{1,2})\s+(.*)$/);
    if(h){const el=document.createElement(h[1].length===1?'h1':'h2');appendInline(el,h[2].replace(/\*\*/g,''));root.appendChild(el);list=null;continue}
    if(line.startsWith('> ')){const q=document.createElement('blockquote');appendInline(q,line.slice(2).replace(/\*\*/g,''));root.appendChild(q);list=null;continue}
    if(line.startsWith('- ')){if(!list){list=document.createElement('ul');root.appendChild(list)}const li=document.createElement('li');appendInline(li,line.slice(2).replace(/\*\*/g,''));list.appendChild(li);continue}
    const p=document.createElement('p');appendInline(p,line.replace(/\*\*/g,'').replace(/`/g,''));root.appendChild(p);list=null;
  }
  return root;
}
function renderStages(stages){
  const wrap=document.createElement('div');wrap.className='stages';
  for(const s of stages||[]){const e=document.createElement('div');e.className='stage '+s.status;const b=document.createElement('b'),small=document.createElement('small');b.textContent=(s.label||s.id||'Stage')+' · '+s.status;small.textContent=s.detail||'';e.append(b,small);wrap.appendChild(e)}
  return wrap;
}
function isPrimary(a){return /_report\.(docx|pdf|md)$/i.test(a.name)||/\.pptx$/i.test(a.name)}
function renderArtifacts(items){
  const wrap=document.createElement('div'),primary=document.createElement('div'),tech=document.createElement('details');wrap.className='artifactWrap';primary.className='downloads';tech.className='tech';
  const summary=document.createElement('summary');summary.textContent='Technical evidence / 監査用データ';tech.appendChild(summary);let techCount=0;
  for(const a of items||[]){const x=document.createElement('a');x.href=a.url;x.textContent='↓ '+a.name;if(isPrimary(a)){if(/_report\.(docx|pdf)$/i.test(a.name))x.className='primaryFile';primary.appendChild(x)}else{tech.appendChild(x);techCount++}}
  if(primary.children.length)wrap.appendChild(primary);if(techCount)wrap.appendChild(tech);return wrap;
}
async function copyAnswer(node){
  const text=node.dataset.answer||'';try{await navigator.clipboard.writeText(text)}catch(e){const t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}
  showToast('Answer copied');
}
function renderActions(node,job){
  const old=node.querySelector('.answerTools');if(old)old.remove();if(!job?.answer)return;
  const bar=document.createElement('div');bar.className='answerTools';const b=document.createElement('button');b.type='button';b.textContent='Copy answer';b.onclick=()=>copyAnswer(node);bar.appendChild(b);node.insertBefore(bar,node.querySelector('.bubble').nextSibling);
}
function ensureNotEmpty(){document.getElementById('emptyState')?.remove()}
function add(who,text,cls='',job=null){
  ensureNotEmpty();const d=document.createElement('div');d.className='msg '+cls;const h=document.createElement('div');h.className='who';h.textContent=who;d.appendChild(h);
  if(job)d.appendChild(renderStages(job.stages));const b=document.createElement('div');b.className='bubble';if(cls.includes('user'))b.textContent=text;else b.appendChild(renderReport(text));d.appendChild(b);
  d.dataset.answer=job?.answer||text;if(job){renderActions(d,job);if(job.artifacts?.length)d.appendChild(renderArtifacts(job.artifacts))}messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d;
}
function updateNode(node,j){
  node.querySelector('.stages')?.remove();node.insertBefore(renderStages(j.stages),node.querySelector('.bubble'));
  const text=(j.status==='queued'||j.status==='running')?'WorkSpace is processing…':(j.answer||(j.error||j.status));
  const b=node.querySelector('.bubble');b.innerHTML='';b.appendChild(renderReport(text));node.dataset.answer=j.answer||'';renderActions(node,j);
  node.querySelector('.artifactWrap')?.remove();
  if(j.artifacts?.length)node.appendChild(renderArtifacts(j.artifacts));if(j.status==='failed'&&!j.answer)node.classList.add('error');
}
async function api(url,opt={}){
  const headers={...(opt.body?{'Content-Type':'application/json'}:{}),...(opt.headers||{})};
  const r=await fetch(url,{credentials:'same-origin',...opt,headers});
  let data={};try{data=await r.json()}catch(e){data={error:r.statusText||'Request failed'}}
  if(r.status===401){document.getElementById('login').classList.remove('hidden');throw new Error('Authentication required')}
  if(!r.ok)throw new Error(data.error||r.statusText);return data;
}
async function login(){
  const key=document.getElementById('key').value;
  try{await api('/api/login',{method:'POST',body:JSON.stringify({token:key})});document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';await bootstrap()}
  catch(e){document.getElementById('loginErr').textContent=e.message}
}
async function loadRecent(){
  const d=await api('/api/recent');messages.innerHTML='';
  if(!d.jobs?.length){const e=document.createElement('div');e.id='emptyState';e.className='empty-state';e.textContent='Your local WorkSpace conversation will appear here.';messages.appendChild(e);return}
  for(const j of [...d.jobs].reverse()){add('You',j.message,'user');const text=(j.status==='completed'||j.status==='blocked')?j.answer:(j.status==='failed'?(j.error||'Failed'):'['+j.status+']');add('WorkSpace',text,j.status==='failed'?'error':'',j)}
}
async function bootstrap(){state.capabilities=await api('/api/capabilities');renderCapabilities();await loadRecent()}
function fileBase64(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>{const v=String(reader.result||'');resolve(v.includes(',')?v.split(',',2)[1]:v)};reader.onerror=()=>reject(reader.error||new Error('File read failed'));reader.readAsDataURL(file)})}
async function uploadOne(file){
  const max=state.capabilities?.limits?.max_upload_bytes||16777216;if(file.size>max)throw new Error(file.name+': maximum upload size is '+Math.floor(max/1048576)+' MiB');
  const data=await fileBase64(file);return api('/api/upload',{method:'POST',body:JSON.stringify({name:file.name,type:file.type||'',data_base64:data})});
}
async function poll(id,node){
  try{const j=await api('/api/jobs/'+id);if(j.status==='queued'||j.status==='running'){updateNode(node,j);setTimeout(()=>poll(id,node),1600);return}updateNode(node,j)}
  catch(e){node.querySelector('.bubble').textContent=e.message;node.classList.add('error')}
}
async function sendMsg(){
  const text=input.value.trim();if(!text)return;
  const maxCount=state.capabilities?.limits?.max_uploads_per_task||8;
  if(state.selectedFiles.length+state.selectedUploads.length>maxCount){showToast('At most '+maxCount+' attachments per request');return}
  sendBtn.disabled=true;closeMenu();
  const names=[...state.selectedFiles.map(f=>f.name),...state.selectedUploads.map(u=>u.name)];
  add('You',text+(names.length?'\n\nAttached: '+names.join(', '):''),'user');
  const pending=add('WorkSpace',state.selectedFiles.length?'Uploading and validating files…':'Queued…','',{answer:'',stages:[{label:'Research',status:'queued'},{label:'Presentation',status:'queued'},{label:'Human Report',status:'queued'}],artifacts:[]});
  try{
    const uploadIds=state.selectedUploads.map(x=>x.upload_id);
    for(let i=0;i<state.selectedFiles.length;i++){pending.querySelector('.bubble').textContent='Uploading '+(i+1)+'/'+state.selectedFiles.length+': '+state.selectedFiles[i].name;const result=await uploadOne(state.selectedFiles[i]);uploadIds.push(result.upload_id)}
    const d=await api('/api/chat',{method:'POST',body:JSON.stringify({message:text,language:document.getElementById('lang').value,format:document.getElementById('fmt').value,upload_ids:[...new Set(uploadIds)],mode:state.requestMode,effort:document.getElementById('effort').value})});
    input.value='';updateInputHeight();state.selectedFiles=[];state.selectedUploads=[];renderAttachments();setMode('chat');updateNode(pending,d);poll(d.job_id,pending);
  }catch(e){pending.querySelector('.bubble').textContent=e.message;pending.classList.add('error')}
  finally{sendBtn.disabled=false}
}
async function openLibrary(){
  const f=feature('library');if(!f.enabled){showToast(f.reason||'Library unavailable');return}
  closeMenu();libraryModal.classList.add('open');libraryList.innerHTML='<div class="library-empty">Loading…</div>';
  try{
    const d=await api('/api/uploads');state.libraryDraft=new Set(state.selectedUploads.map(x=>x.upload_id));libraryList.innerHTML='';
    if(!d.uploads?.length){libraryList.innerHTML='<div class="library-empty">No validated uploads from this client yet.</div>';return}
    for(const u of d.uploads){
      const row=document.createElement('label');row.className='library-item';const check=document.createElement('input');check.type='checkbox';check.checked=state.libraryDraft.has(u.upload_id);check.onchange=()=>{if(check.checked)state.libraryDraft.add(u.upload_id);else state.libraryDraft.delete(u.upload_id)};
      const body=document.createElement('div');const name=document.createElement('div');name.className='library-name';name.textContent=u.name;const meta=document.createElement('div');meta.className='library-meta';meta.textContent=u.kind+' · '+Math.ceil((u.size||0)/1024)+' KB';body.append(name,meta);const tag=document.createElement('div');tag.className='library-meta';tag.textContent=(u.document_count||0)+' docs · '+(u.image_count||0)+' images';row.append(check,body,tag);row.dataset.upload=JSON.stringify(u);libraryList.appendChild(row);
    }
  }catch(e){libraryList.innerHTML='';const x=document.createElement('div');x.className='library-empty';x.textContent=e.message;libraryList.appendChild(x)}
}
function applyLibrary(){
  const max=state.capabilities?.limits?.max_uploads_per_task||8;const chosen=[];
  for(const row of libraryList.querySelectorAll('.library-item')){const u=JSON.parse(row.dataset.upload||'{}');if(state.libraryDraft.has(u.upload_id))chosen.push(u)}
  if(chosen.length+state.selectedFiles.length>max){showToast('At most '+max+' attachments per request');return}
  state.selectedUploads=chosen;renderAttachments();libraryModal.classList.remove('open');
}
function actionClick(action){
  const f=feature(action);if(!f.enabled){showToast(f.reason||'This capability is unavailable');return}
  if(action==='upload'){closeMenu();fileInput.click();return}
  if(action==='library'){openLibrary();return}
  if(action==='web_search'){setMode('web_search');closeMenu();showToast('Web search mode selected');return}
  if(action==='deep_research'){setMode('deep_research');closeMenu();showToast('Deep research mode selected');return}
  showToast(f.reason||'Capability selected');
}

plusBtn.onclick=toggleMenu;
document.addEventListener('click',e=>{if(!plusMenu.contains(e.target)&&!plusBtn.contains(e.target))closeMenu()});
plusMenu.addEventListener('click',e=>{const row=e.target.closest('[data-action]');if(row)actionClick(row.dataset.action)});
fileInput.addEventListener('change',()=>{const max=state.capabilities?.limits?.max_uploads_per_task||8;state.selectedFiles=Array.from(fileInput.files||[]).slice(0,max);fileInput.value='';renderAttachments()});
document.getElementById('micBtn').onclick=()=>{const f=feature('voice_input');if(!f.enabled){showToast(f.reason||'Voice input unavailable');return}showToast('Voice input ready')};
document.getElementById('clearModeBtn').onclick=()=>setMode('chat');
document.getElementById('loginBtn').onclick=login;
document.getElementById('key').addEventListener('keydown',e=>{if(e.key==='Enter')login()});
document.getElementById('libraryClose').onclick=()=>libraryModal.classList.remove('open');
document.getElementById('libraryCancel').onclick=()=>libraryModal.classList.remove('open');
document.getElementById('libraryApply').onclick=applyLibrary;
document.getElementById('recentBtn').onclick=()=>loadRecent().catch(e=>showToast(e.message));
document.getElementById('clearBtn').onclick=()=>{messages.innerHTML='<div class="empty-state" id="emptyState">Local view cleared. Server history was not deleted.</div>';showToast('Local view cleared only')};
sendBtn.onclick=sendMsg;
input.addEventListener('input',updateInputHeight);
input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg()}else if(e.key==='Escape')closeMenu()});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeMenu();libraryModal.classList.remove('open')}});
(async()=>{try{await api('/api/recent');document.getElementById('login').classList.add('hidden');await bootstrap()}catch(e){}})();
</script>
</body>
</html>"""

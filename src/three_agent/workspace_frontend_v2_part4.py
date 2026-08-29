from __future__ import annotations

PART_4 = r"""        <div class="empty-sub">Your chat history stays in the local WorkSpace database.</div>
      </div>
    </div>
  </main>
</div>

<div class="composer-wrap">
  <div class="composer-area">
    <div class="disclaimer">WorkSpace may make mistakes. Check important info.</div>
    <div id="attachments" class="attachments"></div>
    <div id="modePill" class="mode-pill"><span id="modeLabel"></span><button type="button" id="clearMode">×</button></div>

    <div class="plus-menu" id="plusMenu">
      <button class="menu-row" type="button" data-action="upload">
        <span class="menu-icon white"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg></span>
        <span><span class="menu-title">Add photos & files</span><span class="menu-sub">Secure local upload</span></span><span class="menu-state">Ready</span>
      </button>
      <button class="menu-row" type="button" data-action="library">
        <span class="menu-icon blue"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 15 3-3 2 2 3-4 3 5"/></svg></span>
        <span><span class="menu-title">Add from library</span><span class="menu-sub">Reuse your validated uploads</span></span><span class="menu-state">Ready</span>
      </button>
      <button class="menu-row" type="button" data-action="image_generation">
        <span class="menu-icon purple"><svg viewBox="0 0 24 24"><path d="m12 3 1.2 3.5L17 8l-3.8 1.5L12 13l-1.2-3.5L7 8l3.8-1.5z"/><path d="m18 13 .8 2.2L21 16l-2.2.8L18 19l-.8-2.2L15 16l2.2-.8z"/></svg></span>
        <span><span class="menu-title">Create image</span><span class="menu-sub">Local image model only</span></span><span class="menu-state">Not configured</span>
      </button>
      <button class="menu-row" type="button" data-action="web_search">
        <span class="menu-icon blue"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4a13 13 0 0 1 0 16M12 4a13 13 0 0 0 0 16"/></svg></span>
        <span><span class="menu-title">Web search</span><span class="menu-sub">Policy-authorized public research</span></span><span class="menu-state">Policy</span>
      </button>
      <button class="menu-row" type="button" data-action="deep_research">
        <span class="menu-icon green"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4M8 11h6M11 8v6"/></svg></span>
        <span><span class="menu-title">Deep research</span><span class="menu-sub">Thorough evidence-bounded workflow</span></span><span class="menu-state">Ready</span>
      </button>
      <button class="menu-row" type="button" data-action="github">
        <span class="menu-icon white"><svg viewBox="0 0 24 24"><path d="M9 19c-4 1.2-4-2-5-2.5M14 22v-3.1c0-.9.1-1.5-.5-2.1 2.8-.3 5.7-1.4 5.7-6.2a4.9 4.9 0 0 0-1.3-3.4 4.6 4.6 0 0 0-.1-3.4S16.8 3.4 14 5a11.7 11.7 0 0 0-5 0C6.2 3.4 5.2 3.8 5.2 3.8a4.6 4.6 0 0 0-.1 3.4 4.9 4.9 0 0 0-1.3 3.4c0 4.8 2.9 5.9 5.7 6.2-.5.5-.6 1-.6 2.1V22"/></svg></span>
        <span><span class="menu-title">GitHub</span><span class="menu-sub">Repository access</span></span><span class="menu-state">Operator only</span>
      </button>
      <div class="menu-divider"></div>
      <div class="menu-options">
        <label>Response language<select id="lang"><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>
        <label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + Slide PDF</option><option value="all">Report + PPTX + PDF</option></select></label>
      </div>
    </div>

    <div class="composer">
      <button class="circle-btn" id="plusBtn" type="button" aria-label="Open tools">
        <svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>
      </button>
      <textarea id="input" placeholder="Ask WorkSpace" rows="1"></textarea>
      <div class="composer-actions">
        <select class="effort-select" id="effort" aria-label="Reasoning effort"><option value="standard">Standard</option><option value="high" selected>High</option></select>
        <div class="vline"></div>
        <button class="circle-btn" id="micBtn" type="button" aria-label="Voice input" aria-disabled="true">
          <svg viewBox="0 0 24 24"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.5 11.5a6.5 6.5 0 0 0 13 0M12 18v3M9 21h6"/></svg>
        </button>
        <button class="circle-btn" id="sendBtn" type="button" aria-label="Send">
          <svg viewBox="0 0 24 24"><path d="M12 19V5M6.5 10.5 12 5l5.5 5.5"/></svg>
        </button>
      </div>
    </div>
    <input id="fileInput" type="file" multiple hidden accept=".txt,.md,.markdown,.html,.htm,.zip,.png,.jpg,.jpeg,.webp,text/plain,text/markdown,text/html,application/zip,image/png,image/jpeg,image/webp">
  </div>
</div>

<div class="library-modal" id="libraryModal">
  <div class="library-card">
    <div class="library-head"><h2>Your WorkSpace library</h2><button class="soft-btn" id="closeLibrary" type="button">Close</button></div>
    <div class="library-list" id="libraryList"></div>
    <div class="library-foot"><button class="soft-btn" id="libraryCancel" type="button">Cancel</button><button class="soft-btn primary" id="libraryAdd" type="button">Add selected</button></div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const messages=document.getElementById('messages'),input=document.getElementById('input');
const state={
  capabilities:null,selectedFiles:[],selectedLibrary:new Map(),requestMode:'chat',
  currentConversationId:null,conversations:[],searchQuery:'',searchTimer:null,
  session:null,sidebarCollapsed:localStorage.getItem('workspace.sidebarCollapsed')==='1'
};
function svgChat(){return '<svg viewBox="0 0 24 24"><path d="M20 15a4 4 0 0 1-4 4H8l-4 2 1.2-4.2A7 7 0 0 1 4 13V9a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4z"/></svg>'}
function showToast(text){const e=document.getElementById('toast');e.textContent=text;e.classList.add('show');clearTimeout(showToast.t);showToast.t=setTimeout(()=>e.classList.remove('show'),2500)}
function hideEmpty(){const e=document.getElementById('emptyState');if(e)e.remove()}
"""

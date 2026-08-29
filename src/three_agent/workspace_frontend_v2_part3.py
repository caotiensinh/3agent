from __future__ import annotations

PART_3 = r""".library-modal{position:fixed;inset:0;background:rgba(0,0,0,.58);z-index:30;display:none;align-items:center;justify-content:center;padding:20px}.library-modal.open{display:flex}.library-card{width:min(680px,96vw);max-height:76vh;display:flex;flex-direction:column;background:#1b1c20;border:1px solid #44474f;border-radius:20px;box-shadow:var(--shadow)}.library-head{display:flex;align-items:center;padding:16px 18px;border-bottom:1px solid #36383f}.library-head h2{font-size:17px;margin:0}.library-head button{margin-left:auto}.library-list{overflow:auto;padding:8px}.library-empty{padding:30px;color:var(--muted);text-align:center}.library-item{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:10px;border-radius:12px}.library-item:hover{background:#24262b}.library-item input{width:16px;height:16px}.library-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.library-meta{font-size:11px;color:#92959c}.library-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 16px;border-top:1px solid #36383f}
.soft-btn{border:1px solid #41444b;background:#26282d;border-radius:10px;padding:8px 12px;cursor:pointer}.soft-btn.primary{background:#e8e9ed;color:#111;border-color:#e8e9ed;font-weight:650}.toast{position:fixed;left:calc(50% + 143px);bottom:122px;transform:translateX(-50%);background:#292b30;border:1px solid #484b53;border-radius:12px;padding:9px 13px;color:#e5e6e9;font-size:12px;z-index:40;box-shadow:var(--shadow);opacity:0;pointer-events:none;transition:.18s}body.sidebar-collapsed .toast{left:calc(50% + 35px)}.toast.show{opacity:1}
#login{position:fixed;inset:0;background:#090a0c;z-index:50;display:flex;align-items:center;justify-content:center}.login-card{width:min(420px,90vw);background:#191a1e;border:1px solid #3b3d44;border-radius:20px;padding:25px;box-shadow:var(--shadow)}.login-card h2{margin:0 0 6px}.login-card p{color:var(--muted)}.login-card input{width:100%;background:#24262b;color:var(--text);border:1px solid #41434a;border-radius:11px;padding:11px 12px;margin:6px 0 12px;outline:0}.login-card button{width:100%}.login-error{color:var(--danger);font-size:12px}

@media(max-width:760px){
  .sidebar{width:286px;box-shadow:18px 0 45px rgba(0,0,0,.35)}.sidebar.collapsed{width:0;border:0}.sidebar.collapsed .sidebar-top,.sidebar.collapsed .side-nav,.sidebar.collapsed .account-wrap{display:none}
  .main-shell,body.sidebar-collapsed .main-shell{margin-left:0}.composer-wrap,body.sidebar-collapsed .composer-wrap{left:0}.mobile-menu{display:grid;width:38px;height:38px;border:0;background:transparent;border-radius:10px;place-items:center;margin-right:8px}.mobile-menu:hover{background:#18191c}.mobile-menu svg{width:21px;height:21px}.security-badge{display:none}
  .stages{grid-template-columns:1fr}.user .bubble{max-width:92%}.menu-options{grid-template-columns:1fr}.toast,body.sidebar-collapsed .toast{left:50%}
}
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

<aside class="sidebar" id="sidebar">
  <div class="sidebar-top">
    <div class="workspace-logo">
      <span class="logo-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M12 2.8 19.2 7v10L12 21.2 4.8 17V7z"/><path d="m8.2 9.2 3.8-2.1 3.8 2.1v5.6L12 16.9l-3.8-2.1z"/><path d="M12 7.1v9.8"/></svg>
      </span>
      <span class="logo-text">WorkSpace</span>
    </div>
    <button id="sidebarToggle" class="sidebar-toggle" type="button" aria-label="Collapse sidebar">
      <svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="M9 4v16"/></svg>
    </button>
  </div>

  <nav class="side-nav">
    <button class="side-action" id="newChatBtn" type="button">
      <svg viewBox="0 0 24 24"><path d="M12 20H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7"/><path d="m15 5 4 4"/><path d="M13 11 19.5 4.5a1.4 1.4 0 0 1 2 2L15 13l-4 1z"/></svg>
      <span>New chat</span>
    </button>
    <button class="side-action" id="historySearchBtn" type="button">
      <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
      <span>Search chats</span>
    </button>
  </nav>

  <div class="history-search hidden" id="historySearchBox">
    <input id="historySearchInput" type="search" autocomplete="off" placeholder="Search history">
    <button id="clearHistorySearch" type="button" aria-label="Clear search">
      <svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>
    </button>
  </div>

  <div class="history-scroll">
    <section class="history-section" id="pinnedSection">
      <div class="history-heading">Pinned</div>
      <div id="pinnedList"></div>
    </section>
    <section class="history-section">
      <div class="history-heading" id="historyHeading">Chats</div>
      <div id="historyList"></div>
    </section>
  </div>

  <div class="account-wrap">
    <div class="account-menu" id="accountMenu">
      <button type="button" id="logoutBtn">Log out</button>
    </div>
    <button class="account-btn" id="accountBtn" type="button">
      <span class="account-avatar" id="accountAvatar">W</span>
      <span class="account-copy">
        <span class="account-name" id="accountName">WorkSpace User</span>
        <span class="account-sub" id="accountSub">Local LAN session</span>
      </span>
      <span class="account-more"><svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg></span>
    </button>
  </div>
</aside>

<div class="main-shell">
  <header class="topbar">
    <button class="mobile-menu" id="mobileMenuBtn" type="button" aria-label="Open sidebar">
      <svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
    </button>
    <div class="conversation-name" id="conversationName">New chat</div>
    <div class="top-spacer"></div>
    <div class="security-badge">Local-first</div>
  </header>
  <main id="messages">
    <div class="empty-state" id="emptyState">
      <div class="empty-inner">
        <div class="empty-logo"><svg viewBox="0 0 24 24"><path d="M12 2.8 19.2 7v10L12 21.2 4.8 17V7z"/><path d="m8.2 9.2 3.8-2.1 3.8 2.1v5.6L12 16.9l-3.8-2.1z"/></svg></div>
        <div class="empty-title">How can WorkSpace help?</div>
"""

from __future__ import annotations

PART_1 = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WorkSpace</title>
<style>
:root{
  color-scheme:dark;
  --bg:#08090b;--panel:#17181b;--panel2:#202124;--panel3:#292a2e;
  --line:#303238;--line2:#444750;--text:#f2f3f5;--muted:#9b9ea5;
  --accent:#5b7cfa;--danger:#ff9696;--ok:#75d49a;--sidebar-w:286px;
  --shadow:0 18px 55px rgba(0,0,0,.42)
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:radial-gradient(circle at 52% 18%,#11131a 0,#090a0d 35%,#07080a 72%);color:var(--text);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow:hidden}
button,select,textarea,input{font:inherit}button{color:inherit}.hidden{display:none!important}
svg{stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}

.sidebar{position:fixed;left:0;top:0;bottom:0;width:286px;background:#050506;border-right:1px solid #1d1e21;z-index:15;display:flex;flex-direction:column;transition:width .18s ease;overflow:hidden}
.sidebar.collapsed{width:70px}
.sidebar-top{height:68px;display:flex;align-items:center;padding:0 13px;gap:9px;flex:0 0 auto}
.workspace-logo{display:flex;align-items:center;gap:10px;min-width:0;font-weight:700;font-size:18px;letter-spacing:-.02em;flex:1}
.logo-mark{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;flex:0 0 auto;background:linear-gradient(145deg,#1c2030,#101116);border:1px solid #34384d;color:#dfe4ff}
.logo-mark svg{width:23px;height:23px}
.logo-text{white-space:nowrap;overflow:hidden;transition:opacity .12s}
.sidebar.collapsed .logo-text{opacity:0;width:0}
.sidebar-toggle{width:36px;height:36px;border:0;background:transparent;border-radius:10px;display:grid;place-items:center;cursor:pointer;color:#c7c9ce;flex:0 0 auto}
.sidebar-toggle:hover,.side-action:hover,.account-btn:hover{background:#17181b}
.sidebar-toggle svg{width:20px;height:20px}
.sidebar.collapsed .sidebar-toggle{position:absolute;left:17px;top:79px}

.side-nav{padding:5px 9px;display:flex;flex-direction:column;gap:2px;flex:0 0 auto}
.side-action{height:44px;width:100%;border:0;background:transparent;border-radius:10px;display:flex;align-items:center;gap:11px;padding:0 11px;cursor:pointer;text-align:left;color:#ececef;white-space:nowrap}
.side-action svg{width:21px;height:21px;flex:0 0 auto}.side-action span{overflow:hidden;text-overflow:ellipsis}
.sidebar.collapsed .side-nav{padding-top:53px}
.sidebar.collapsed .side-action{width:52px;justify-content:center;padding:0;margin:auto}.sidebar.collapsed .side-action span{display:none}

.history-search{margin:5px 12px 4px;position:relative}
.history-search input{width:100%;height:37px;background:#111215;border:1px solid #292b30;color:#e7e8eb;border-radius:10px;padding:0 34px 0 11px;outline:0}
.history-search input:focus{border-color:#50566f}.history-search button{position:absolute;right:4px;top:4px;width:29px;height:29px;border:0;background:transparent;border-radius:8px;display:grid;place-items:center;cursor:pointer;color:#92959c}
.history-search button svg{width:16px;height:16px}.sidebar.collapsed .history-search{display:none}

.history-scroll{flex:1;overflow:auto;padding:6px 9px 12px;scrollbar-width:thin;scrollbar-color:#2d2f34 transparent}
.history-section{margin-top:13px}.history-heading{font-size:12px;font-weight:650;color:#878a90;padding:4px 10px 7px;white-space:nowrap}
.history-empty{font-size:12px;color:#676a70;padding:8px 10px}
.conversation-row{height:39px;border-radius:9px;display:flex;align-items:center;gap:7px;padding:0 6px 0 10px;cursor:pointer;color:#dfe0e3;position:relative}
.conversation-row:hover,.conversation-row.active{background:#18191c}.conversation-row.active{color:#fff}
.conversation-icon{width:18px;height:18px;flex:0 0 auto;color:#b9bbc1}.conversation-icon svg{width:18px;height:18px}
.conversation-title{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.pin-btn{width:28px;height:28px;border:0;background:transparent;border-radius:8px;display:grid;place-items:center;cursor:pointer;color:#8f9298;opacity:0}
.conversation-row:hover .pin-btn,.conversation-row.active .pin-btn{opacity:1}.pin-btn.pinned{opacity:1;color:#d4d8ff}.pin-btn:hover{background:#26272b}.pin-btn svg{width:15px;height:15px}
.sidebar.collapsed .history-scroll{display:none}

.account-wrap{border-top:1px solid #1d1e21;padding:9px;position:relative;flex:0 0 auto}
.account-btn{width:100%;height:53px;border:0;background:transparent;border-radius:11px;display:flex;align-items:center;gap:10px;padding:0 9px;cursor:pointer;text-align:left}
.account-avatar{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto;background:#202449;border:1px solid #4b53a4;font-weight:700;font-size:13px;position:relative}
.account-avatar::after{content:"";position:absolute;right:-1px;bottom:0;width:8px;height:8px;border-radius:50%;background:#4bd384;border:2px solid #050506}
.account-copy{min-width:0;flex:1}.account-name{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.account-sub{font-size:11px;color:#888b91;white-space:nowrap}
.account-more{color:#898c92}.account-more svg{width:18px;height:18px}
.sidebar.collapsed .account-btn{width:52px;justify-content:center;padding:0;margin:auto}.sidebar.collapsed .account-copy,.sidebar.collapsed .account-more{display:none}
.account-menu{position:absolute;left:10px;right:10px;bottom:69px;background:#202125;border:1px solid #3a3c43;border-radius:14px;padding:7px;box-shadow:var(--shadow);display:none}
.account-menu.open{display:block}.account-menu button{width:100%;height:39px;border:0;background:transparent;border-radius:9px;text-align:left;padding:0 11px;cursor:pointer}.account-menu button:hover{background:#2b2c31}
.sidebar.collapsed .account-menu{left:68px;right:auto;width:210px;bottom:10px}

.main-shell{height:100vh;margin-left:286px;transition:margin-left .18s ease;display:flex;flex-direction:column}
body.sidebar-collapsed .main-shell{margin-left:70px}
.topbar{height:68px;display:flex;align-items:center;padding:0 24px;border-bottom:1px solid rgba(36,38,43,.45);flex:0 0 auto}
.mobile-menu{display:none}.conversation-name{font-weight:600;color:#e9eaed;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.top-spacer{flex:1}
.security-badge{font-size:11px;color:#777b83;border:1px solid #292b31;border-radius:999px;padding:5px 9px}

"""

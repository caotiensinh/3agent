from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v12 import WORKSPACE_HTML_V12


html = WORKSPACE_HTML_V12

# Language is authoritative per current request. Keep a hidden `auto` control only
# because workflow-studio JavaScript shares the same request payload field. There
# is no session-level language picker in the user-facing tools menu anymore.
html = _replace_once(
    html,
    '<label>Response language<select id="lang"><option value="auto" selected>Auto · follow current request</option><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    '<select id="lang" hidden aria-hidden="true"><option value="auto" selected>Auto</option></select>',
    "hide-session-language-selector",
)

# Add connector discovery rows at the stable menu boundary. The existing upload,
# library, image, web, deep-research, and GitHub rows are preserved unchanged.
# Discovery rows are visible but receive no runtime authority until capabilities
# explicitly enable a compatible local connector.
integration_rows = r'''
      <button class="menu-row" type="button" data-action="figma" data-connect-action="true" role="menuitem">
        <span class="menu-icon white">F</span>
        <span><div class="menu-title">Figma</div><div class="menu-sub">Design-to-code workflows</div></span><span class="menu-state">Connect</span>
      </button>
      <button class="menu-row" type="button" data-action="canva" data-connect-action="true" role="menuitem">
        <span class="menu-icon blue">C</span>
        <span><div class="menu-title">Canva</div><div class="menu-sub">Create, review, and edit designs</div></span><span class="menu-state">Connect</span>
      </button>
      <button class="menu-row" type="button" data-action="gmail" data-connect-action="true" role="menuitem">
        <span class="menu-icon white">M</span>
        <span><div class="menu-title">Gmail</div><div class="menu-sub">Read and manage Gmail</div></span><span class="menu-state">Connect</span>
      </button>
'''
html = _replace_once(
    html,
    '      <div class="menu-divider"></div>\n      <div class="menu-options">',
    integration_rows + '      <div class="menu-divider"></div>\n      <div class="menu-options">',
    "integration-menu-boundary",
)

# For connector discovery rows that are not yet present in the runtime capability
# registry, show `Connect` rather than a misleading generic `Unavailable`. Clicking
# still fails closed and explains that the connector is not configured.
html = _replace_once(
    html,
    "function feature(name){return state.capabilities?.features?.[name]||{enabled:false,reason:'Capability information is unavailable.'}}",
    "function feature(name){const configured=state.capabilities?.features?.[name];if(configured)return configured;const connect=new Set(['figma','canva','gmail']);return{enabled:false,state_label:connect.has(name)?'Connect':'Unavailable',reason:connect.has(name)?'This connector is not configured for the local WorkSpace runtime.':'Capability information is unavailable.'}}",
    "connector-discovery-state",
)

# Make the request-driven language behavior explicit in the output selector area
# without adding another control the user has to maintain per conversation.
html = _replace_once(
    html,
    '<label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + PDF</option><option value="all">Report + PPTX + PDF</option></select></label>',
    '<label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + PDF</option><option value="all">Report + PPTX + PDF</option></select></label><span class="menu-sub">Language follows each current request automatically.</span>',
    "request-language-hint",
)

WORKSPACE_HTML_V13 = html

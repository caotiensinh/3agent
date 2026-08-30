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

# Match the compact one-plus-menu interaction expected by users. Integrations are
# visible discovery points but remain fail-closed unless the local capability
# registry explicitly enables them. Bind to the exact v12 GitHub row and add the
# menuitem role while inserting the new discovery rows.
figma_canva = r'''
      <button class="menu-row" type="button" data-action="figma" data-connect-action="true" role="menuitem">
        <span class="menu-icon white">F</span>
        <span><span class="menu-title">Figma</span><span class="menu-sub">Design-to-code workflows</span></span><span class="menu-state">Connect</span>
      </button>
      <button class="menu-row" type="button" data-action="canva" data-connect-action="true" role="menuitem">
        <span class="menu-icon blue">C</span>
        <span><span class="menu-title">Canva</span><span class="menu-sub">Create, review, and edit designs</span></span><span class="menu-state">Connect</span>
      </button>
'''
html = _replace_once(
    html,
    '      <button class="menu-row" type="button" data-action="github">',
    figma_canva + '      <button class="menu-row" type="button" data-action="github" role="menuitem">',
    "integration-menu-before-github",
)

gmail = r'''
      <button class="menu-row" type="button" data-action="gmail" data-connect-action="true" role="menuitem">
        <span class="menu-icon white">M</span>
        <span><span class="menu-title">Gmail</span><span class="menu-sub">Read and manage Gmail</span></span><span class="menu-state">Connect</span>
      </button>
'''
html = _replace_once(
    html,
    '      <div class="menu-divider"></div>\n      <div class="menu-options">',
    gmail + '      <div class="menu-divider"></div>\n      <div class="menu-options">',
    "integration-menu-gmail",
)

# Preserve the existing capability lookup path. Connector discovery is display
# only: an absent registry entry is still disabled and clicking it follows the
# existing `unavailable(action)` path rather than receiving a synthetic capability.
html = _replace_once(
    html,
    "function cap(name){return state.capabilities&&state.capabilities.features&&state.capabilities.features[name]?state.capabilities.features[name]:{enabled:false,state_label:'Unavailable',reason:'Capability unavailable'}}",
    "function cap(name){const configured=state.capabilities&&state.capabilities.features&&state.capabilities.features[name];if(configured)return configured;const connect=new Set(['figma','canva','gmail']);return{enabled:false,state_label:connect.has(name)?'Connect':'Unavailable',reason:connect.has(name)?'This connector is not configured for the local WorkSpace runtime.':'Capability unavailable'}}",
    "connector-discovery-state",
)

# Make the request-driven language behavior explicit in the output selector area
# without adding another control the user has to maintain per conversation. Keep
# the exact existing v12 output labels, including "Slide PDF".
html = _replace_once(
    html,
    '<label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + Slide PDF</option><option value="all">Report + PPTX + PDF</option></select></label>',
    '<label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + Slide PDF</option><option value="all">Report + PPTX + PDF</option></select></label><span class="menu-sub">Language follows each current request automatically.</span>',
    "request-language-hint",
)

WORKSPACE_HTML_V13 = html

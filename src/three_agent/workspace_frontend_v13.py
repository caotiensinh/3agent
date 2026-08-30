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

# Add connector discovery rows at the stable menu boundary. Existing upload,
# library, image, web, deep-research, and GitHub rows remain unchanged. Runtime
# capability metadata is authoritative: discovery rows have zero authority until
# a compatible connector is explicitly configured server-side.
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

# Make request-driven language behavior explicit without adding another control
# users must maintain for the whole conversation.
html = _replace_once(
    html,
    '<label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + PDF</option><option value="all">Report + PPTX + PDF</option></select></label>',
    '<label>Output<select id="fmt"><option value="source">Report</option><option value="pptx">Report + PPTX</option><option value="pdf">Report + PDF</option><option value="all">Report + PPTX + PDF</option></select></label><span class="menu-sub">Language follows each current request automatically.</span>',
    "request-language-hint",
)

WORKSPACE_HTML_V13 = html

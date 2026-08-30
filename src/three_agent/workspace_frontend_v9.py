from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v8 import WORKSPACE_HTML_V8


html = WORKSPACE_HTML_V8

html = _replace_once(
    html,
    '<label>Response language<select id="lang"><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    '<label>Response language<select id="lang"><option value="auto" selected>Auto · follow current request</option><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    "response-language-auto",
)

# Workflow Studio must follow the same response-language policy instead of
# silently hard-coding Japanese. The v13 server resolves Auto deterministically.
html = _replace_once(
    html,
    "JSON.stringify({description,language:'ja'})",
    "JSON.stringify({description,language:document.getElementById('lang').value})",
    "workflow-language-selection",
)

WORKSPACE_HTML_V9 = html

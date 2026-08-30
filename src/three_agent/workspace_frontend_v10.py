from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v9 import WORKSPACE_HTML_V9


html = WORKSPACE_HTML_V9

html = _replace_once(
    html,
    '<label>Response language<select id="lang"><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    '<label>Response language<select id="lang"><option value="auto" selected>Auto · follow current request</option><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select></label>',
    "response-language-auto",
)

html = _replace_once(
    html,
    "JSON.stringify({description,language:'ja'})",
    "JSON.stringify({description,language:document.getElementById('lang').value})",
    "workflow-compile-language",
)

html = _replace_once(
    html,
    "JSON.stringify({contract:currentContract(),language:'ja',output_format:'pptx'})",
    "JSON.stringify({contract:currentContract(),language:document.getElementById('lang').value,output_format:'pptx'})",
    "workflow-dispatch-language",
)

WORKSPACE_HTML_V10 = html

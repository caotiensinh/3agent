from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_security_v2 import WORKSPACE_HTML_SECURITY_V2


html = WORKSPACE_HTML_SECURITY_V2

SECURITY_BOUNDARY_CSS = r'''
.security-boundary-intro{border:1px solid #4b4232;background:#1b1710;border-radius:12px;padding:11px 12px;color:#ddc99f;font-size:11px;line-height:1.5;margin-bottom:12px}.security-boundary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-boundary-card{border:1px solid #343840;background:#111317;border-radius:11px;padding:11px}.security-boundary-card b{display:block;font-size:11px;margin-bottom:6px}.security-boundary-state{display:inline-block;border:1px solid #5a4930;border-radius:999px;padding:2px 7px;color:#e3c895;font-size:9px;font-weight:750;letter-spacing:.03em}.security-boundary-card p{margin:7px 0 0;color:#858a94;font-size:10px;line-height:1.45}@media(max-width:760px){.security-boundary-grid{grid-template-columns:1fr}}
'''
html = _replace_once(html, "</style>", SECURITY_BOUNDARY_CSS + "</style>", "security-boundary-css")

html = _replace_once(
    html,
    '        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
    '        <button class="security-tab" data-security-tab="boundaries" id="securityBoundaryTab" type="button">Boundaries</button>\n        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
    "security-boundary-tab",
)

SECURITY_BOUNDARY_MARKUP = r'''
      <div class="security-view" data-security-view="boundaries" id="securityBoundaryView">
        <div class="security-boundary-intro"><strong>Not Implemented — Authority Boundaries</strong><br>These capabilities are intentionally absent from the Security Analyst runtime. Visibility and advisory analysis do not grant execution authority.</div>
        <div class="security-boundary-grid">
          <div class="security-boundary-card"><b>Autonomous network discovery</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No autonomous target discovery or inventory enrollment.</p></div>
          <div class="security-boundary-card"><b>Autonomous active scan</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No port scan, vulnerability scan, or scope expansion initiated by the analyst.</p></div>
          <div class="security-boundary-card"><b>Automatic firewall or block action</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No firewall mutation, host blocking, ACL change, or containment action.</p></div>
          <div class="security-boundary-card"><b>AI-triggered packet capture</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>The analyst cannot start capture. Any bounded incident capture remains a separate explicit admin-approved runner workflow.</p></div>
          <div class="security-boundary-card"><b>Shell or network command execution</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>No shell, SSH, arbitrary command, or device configuration execution from the analyst surface.</p></div>
          <div class="security-boundary-card"><b>Autonomous remediation</b><span class="security-boundary-state">NOT IMPLEMENTED</span><p>Findings and analyst assessments remain advisory; no automatic corrective action is authorized.</p></div>
        </div>
      </div>

'''
html = _replace_once(
    html,
    '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
    SECURITY_BOUNDARY_MARKUP + '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
    "security-boundary-view",
)

WORKSPACE_HTML_SECURITY_V3 = html

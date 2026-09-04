from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v15 import WORKSPACE_HTML_V15


html = WORKSPACE_HTML_V15

SOC_SECURITY_CSS = r'''
.security-soc-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.security-soc-section{margin-top:14px}.security-soc-section h3{font-size:13px;margin:0 0 8px}.security-soc-note{color:#858a94;font-size:10px;line-height:1.45;margin:0 0 8px}.security-truth-state{display:inline-block;border:1px solid #3c414a;border-radius:999px;padding:2px 7px;font-size:9px;font-weight:700;white-space:nowrap}.security-truth-state.verified{border-color:#315a46;color:#b8dbc9}.security-truth-state.inference{border-color:#5a4930;color:#e3c895}.security-truth-state.unknown{border-color:#454954;color:#b7bbc4}@media(max-width:900px){.security-soc-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:640px){.security-soc-grid{grid-template-columns:1fr}}
'''
html = _replace_once(html, "</style>", SOC_SECURITY_CSS + "</style>", "security-soc-css")

html = _replace_once(
    html,
    '        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
    '        <button class="security-tab" data-security-tab="soc" id="securitySocTab" type="button">SOC</button>\n        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
    "security-soc-tab",
)

SOC_SECURITY_MARKUP = r'''
      <div class="security-view" data-security-view="soc" id="securitySocView">
        <div class="security-soc-grid">
          <div class="security-card"><div class="security-card-label">Today high / critical</div><div class="security-card-value" id="securitySocTodayRisk">—</div></div>
          <div class="security-card"><div class="security-card-label">7d high / critical</div><div class="security-card-value" id="securitySoc7dRisk">—</div></div>
          <div class="security-card"><div class="security-card-label">30d high / critical</div><div class="security-card-value" id="securitySoc30dRisk">—</div></div>
          <div class="security-card"><div class="security-card-label">Today data gaps</div><div class="security-card-value" id="securitySocDataGaps">—</div></div>
        </div>

        <section class="security-soc-section" aria-labelledby="securitySocFindingsTitle">
          <h3 id="securitySocFindingsTitle">Findings</h3>
          <div class="security-soc-note">Bounded deterministic findings from the canonical SOC projection.</div>
          <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th><th>Last seen</th><th>Evidence</th></tr></thead><tbody id="securitySocFindingRows"></tbody></table></div>
        </section>

        <section class="security-soc-section" aria-labelledby="securitySocEvidenceTitle">
          <h3 id="securitySocEvidenceTitle">Evidence</h3>
          <div class="security-soc-note">Opaque evidence references only. Raw logs and private asset identity are outside this view.</div>
          <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Evidence reference</th></tr></thead><tbody id="securitySocEvidenceRows"></tbody></table></div>
        </section>

        <section class="security-soc-section" aria-labelledby="securitySocAnalystTitle">
          <h3 id="securitySocAnalystTitle">Analyst assessment</h3>
          <div class="security-soc-note">Enterprise truth states are limited to VERIFIED FACT, INFERENCE and UNKNOWN.</div>
          <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Truth state</th><th>Statement</th><th>Evidence</th></tr></thead><tbody id="securitySocAnalystRows"></tbody></table></div>
        </section>
      </div>

'''
html = _replace_once(
    html,
    '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
    SOC_SECURITY_MARKUP + '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
    "security-soc-view",
)

SOC_SECURITY_JS = r'''
(function(){
const tab=document.getElementById('securitySocTab');
if(!tab)return;
const allowedTruth=new Set(['VERIFIED FACT','INFERENCE','UNKNOWN']);
function clearRows(body){while(body.firstChild)body.removeChild(body.firstChild)}
function emptyRow(body,cols,message){clearRows(body);const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=cols;td.className='security-empty';td.textContent=message;tr.appendChild(td);body.appendChild(tr)}
function cell(tr,value){const td=document.createElement('td');td.textContent=value===null||value===undefined||value===''?'—':String(value);tr.appendChild(td);return td}
function refs(value){return Array.isArray(value)?value.join(', '):'—'}
function renderRisk(d){const risk=d&&d.risk_summary||{};document.getElementById('securitySocTodayRisk').textContent=String(risk.today_open_high_critical??0);document.getElementById('securitySoc7dRisk').textContent=String(risk.rolling_7d_open_high_critical??0);document.getElementById('securitySoc30dRisk').textContent=String(risk.rolling_30d_open_high_critical??0);document.getElementById('securitySocDataGaps').textContent=String(risk.today_data_gaps??0)}
function renderFindings(items){const body=document.getElementById('securitySocFindingRows');clearRows(body);if(!Array.isArray(items)||!items.length){emptyRow(body,6,'No bounded SOC findings.');return}for(const item of items){const tr=document.createElement('tr');cell(tr,item.finding_id);cell(tr,item.severity);cell(tr,item.status);cell(tr,item.category);cell(tr,item.last_seen);cell(tr,refs(item.evidence_refs));body.appendChild(tr)}}
function renderEvidence(items){const body=document.getElementById('securitySocEvidenceRows');clearRows(body);if(!Array.isArray(items)||!items.length){emptyRow(body,1,'No evidence references in this snapshot.');return}for(const ref of items){const tr=document.createElement('tr');cell(tr,ref);body.appendChild(tr)}}
function truthClass(state){if(state==='VERIFIED FACT')return 'verified';if(state==='INFERENCE')return 'inference';return 'unknown'}
function renderAnalyst(items){const body=document.getElementById('securitySocAnalystRows');clearRows(body);if(!Array.isArray(items)||!items.length){emptyRow(body,3,'No enterprise analyst assessment attached to this deterministic snapshot.');return}for(const item of items){if(!allowedTruth.has(item.truth_state))continue;const tr=document.createElement('tr'),stateCell=document.createElement('td'),badge=document.createElement('span');badge.className='security-truth-state '+truthClass(item.truth_state);badge.textContent=item.truth_state;stateCell.appendChild(badge);tr.appendChild(stateCell);cell(tr,item.statement);cell(tr,refs(item.evidence_ids));body.appendChild(tr)}if(!body.children.length)emptyRow(body,3,'No valid enterprise truth-state findings.')} 
async function loadSoc(){try{const d=await api('/api/security/soc');renderRisk(d);renderFindings(d.findings);renderEvidence(d.evidence_refs);renderAnalyst(d.analyst_findings)}catch(e){renderRisk({});emptyRow(document.getElementById('securitySocFindingRows'),6,'SOC snapshot unavailable.');emptyRow(document.getElementById('securitySocEvidenceRows'),1,'SOC snapshot unavailable.');emptyRow(document.getElementById('securitySocAnalystRows'),3,'SOC snapshot unavailable.')}}
tab.addEventListener('click',loadSoc);
})();
'''
html = _replace_once(html, "</body>", "<script>" + SOC_SECURITY_JS + "</script>\n</body>", "security-soc-js")

WORKSPACE_HTML_SECURITY_V2 = html

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

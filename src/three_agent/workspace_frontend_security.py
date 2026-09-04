from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v12 import WORKSPACE_HTML_V12


# Canonical Security Analyst base overlay (formerly the physical V1 module).
html = WORKSPACE_HTML_V12

security_css = r"""
.specialized-section{padding:8px 9px 5px;flex:0 0 auto;border-top:1px solid #151619}.specialized-heading{padding:3px 10px 6px;color:#666a72;font-size:10px;font-weight:750;letter-spacing:.08em}.security-specialized-btn{position:relative}.security-specialized-badge{margin-left:auto;max-width:86px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border:1px solid #343840;border-radius:999px;padding:2px 6px;color:#aeb3bd;font-size:9px}.sidebar.collapsed .specialized-heading{display:none}.sidebar.collapsed .specialized-section{padding:4px 9px}.sidebar.collapsed .security-specialized-btn{width:52px;justify-content:center;padding:0;margin:auto}.sidebar.collapsed .security-specialized-btn .security-label,.sidebar.collapsed .security-specialized-badge{display:none}
.security-surface{display:none;flex:1;min-height:0;overflow:auto;padding:22px 24px 42px;background:radial-gradient(circle at 48% 0,#10141b 0,#090b0f 36%,#08090b 78%)}.security-surface.open{display:block}body.security-analyst-open #messages{display:none}body.security-analyst-open .composer-wrap{display:none}.security-shell{max-width:1240px;margin:0 auto}.security-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:14px}.security-head-copy{flex:1}.security-head h2{margin:0;font-size:22px}.security-sub{color:var(--muted);font-size:12px;margin-top:4px}.security-status-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.security-status-chip{border:1px solid #363a42;border-radius:999px;padding:4px 8px;font-size:10px;color:#b9bdc6}.security-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 14px}.security-tab{border:1px solid #373a42;background:#17191e;color:#cdd0d6;border-radius:9px;padding:7px 10px;cursor:pointer;font-size:12px}.security-tab.active{background:#e7e9ee;color:#111318;border-color:#e7e9ee}.security-view{display:none}.security-view.active{display:block}.security-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.security-card{border:1px solid #30333a;background:#14161a;border-radius:12px;padding:12px;min-width:0}.security-card-label{font-size:10px;color:#81858e;text-transform:uppercase;letter-spacing:.05em}.security-card-value{font-size:20px;font-weight:720;margin-top:3px;overflow:hidden;text-overflow:ellipsis}.security-table-wrap{overflow:auto;border:1px solid #30333a;border-radius:12px;background:#111317}.security-table{width:100%;border-collapse:collapse;min-width:760px}.security-table th,.security-table td{padding:9px 10px;border-bottom:1px solid #282b31;text-align:left;font-size:11px;vertical-align:top}.security-table th{color:#8f939c;font-weight:650;background:#15171b;position:sticky;top:0}.security-table tr.clickable{cursor:pointer}.security-table tr.clickable:hover{background:#1b1e24}.security-empty{padding:28px;color:#777b84;text-align:center}.security-pager{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:9px}.security-pager span{font-size:10px;color:#858992}.security-detail{margin-top:12px;border:1px solid #30333a;border-radius:12px;background:#101216;padding:11px;white-space:pre-wrap;word-break:break-word;font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;max-height:300px;overflow:auto}.security-admin-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-kv{border:1px solid #30333a;border-radius:10px;background:#121418;padding:9px}.security-kv b{display:block;font-size:10px;color:#81858e;margin-bottom:3px}.security-kv span{font-size:12px;word-break:break-word}@media(max-width:900px){.security-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.specialized-section{padding-left:9px;padding-right:9px}.security-surface{padding:16px 12px 30px}.security-grid,.security-admin-grid{grid-template-columns:1fr}.security-head{align-items:center}.security-sub{max-width:75vw}}
"""
html = _replace_once(html, "</style>", security_css + "</style>", "security-analyst-css")

specialized_markup = r'''
  <section class="specialized-section" id="specializedSection">
    <div class="specialized-heading">SPECIALIZED</div>
    <button class="side-action security-specialized-btn" id="securityAnalystBtn" type="button" title="Security Analyst">
      <svg viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5-3.2 8.5-8 10-4.8-1.5-8-5-8-10V6z"/><path d="M8 12h2l1.2-3 1.7 6 1.1-3H17"/></svg>
      <span class="security-label">Security Analyst</span>
      <span class="security-specialized-badge" id="securityAnalystBadge">—</span>
    </button>
  </section>

'''
html = _replace_once(
    html,
    '  <div class="history-search hidden" id="historySearchBox">',
    specialized_markup + '  <div class="history-search hidden" id="historySearchBox">',
    "security-analyst-sidebar",
)

security_markup = r'''
  <section class="security-surface" id="securityAnalystSurface" aria-label="Security Analyst">
    <div class="security-shell">
      <div class="security-head">
        <div class="security-head-copy">
          <h2>Security Analyst</h2>
          <div class="security-sub">Read-only local monitoring view. No remediation, packet capture, policy mutation or network command authority is exposed here.</div>
          <div class="security-status-row">
            <span class="security-status-chip" id="securityHealthChip">Health: —</span>
            <span class="security-status-chip" id="securityHighCriticalChip">High/Critical: —</span>
            <span class="security-status-chip" id="securityCoverageChip">Coverage: —</span>
          </div>
        </div>
        <button class="soft-btn" id="securityAnalystClose" type="button">Close</button>
      </div>
      <div class="security-tabs" role="tablist">
        <button class="security-tab active" data-security-tab="overview" type="button">Overview</button>
        <button class="security-tab" data-security-tab="network" type="button">Network</button>
        <button class="security-tab" data-security-tab="findings" type="button">Findings</button>
        <button class="security-tab" data-security-tab="events" type="button">Events &amp; Logs</button>
        <button class="security-tab" data-security-tab="assets" type="button">Assets</button>
        <button class="security-tab" data-security-tab="reports" type="button">Reports</button>
        <button class="security-tab" data-security-tab="admin" id="securityAdminTab" type="button">Administration</button>
      </div>

      <div class="security-view active" data-security-view="overview">
        <div class="security-grid">
          <div class="security-card"><div class="security-card-label">Health</div><div class="security-card-value" id="securityOverviewHealth">—</div></div>
          <div class="security-card"><div class="security-card-label">High / Critical</div><div class="security-card-value" id="securityOverviewHighCritical">—</div></div>
          <div class="security-card"><div class="security-card-label">Enabled assets</div><div class="security-card-value" id="securityOverviewAssets">—</div></div>
          <div class="security-card"><div class="security-card-label">Latest coverage</div><div class="security-card-value" id="securityOverviewCoverage">—</div></div>
        </div>
        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th><th>Last seen</th></tr></thead><tbody id="securityOverviewFindings"></tbody></table></div>
      </div>

      <div class="security-view" data-security-view="network">
        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Observed</th><th>Asset</th><th>Collector</th><th>Metric</th><th>Status</th><th>Value</th><th>Evidence</th></tr></thead><tbody id="securityNetworkRows"></tbody></table></div>
        <div class="security-pager" id="securityNetworkPager"></div>
      </div>

      <div class="security-view" data-security-view="findings">
        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th><th>Assets</th><th>Last seen</th></tr></thead><tbody id="securityFindingRows"></tbody></table></div>
        <div class="security-pager" id="securityFindingPager"></div>
        <pre class="security-detail" id="securityFindingDetail">Select a finding to inspect its bounded evidence references.</pre>
      </div>

      <div class="security-view" data-security-view="events">
        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Observed</th><th>Source</th><th>Type</th><th>Severity</th><th>Category</th><th>Parser</th><th>Evidence</th></tr></thead><tbody id="securityEventRows"></tbody></table></div>
        <div class="security-pager" id="securityEventPager"></div>
      </div>

      <div class="security-view" data-security-view="assets">
        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Approved asset</th><th>Role</th><th>Enabled</th><th>Data class</th><th>Collectors</th><th>Observed state</th><th>Last observed</th></tr></thead><tbody id="securityAssetRows"></tbody></table></div>
      </div>

      <div class="security-view" data-security-view="reports">
        <div class="security-table-wrap"><table class="security-table"><thead><tr><th>Archive</th><th>Period</th><th>Status</th><th>Attempt</th><th>Updated</th><th>Manifest</th></tr></thead><tbody id="securityReportRows"></tbody></table></div>
        <div class="security-pager" id="securityReportPager"></div>
      </div>

      <div class="security-view" data-security-view="admin">
        <div class="security-admin-grid" id="securityAdminGrid"></div>
      </div>
    </div>
  </section>
'''
html = _replace_once(
    html,
    '  <main id="messages">',
    security_markup + '  <main id="messages">',
    "security-analyst-surface",
)

security_js = r'''
(function(){
const surface=document.getElementById('securityAnalystSurface'),badge=document.getElementById('securityAnalystBadge'),healthChip=document.getElementById('securityHealthChip'),highChip=document.getElementById('securityHighCriticalChip'),coverageChip=document.getElementById('securityCoverageChip');
let securityOpen=false,activeTab='overview',pollHandle=null,previousTitle='',offsets={network:0,findings:0,events:0,reports:0};
const PAGE=50;
function sText(value,fallback='—'){return value===null||value===undefined||value===''?fallback:String(value)}
function sCell(row,value){const td=document.createElement('td');td.textContent=sText(value);row.appendChild(td);return td}
function sEmpty(tbody,message,cols){tbody.innerHTML='';const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=cols;td.className='security-empty';td.textContent=message;tr.appendChild(td);tbody.appendChild(tr)}
function sRows(tbody,items,cols,render){tbody.innerHTML='';if(!items.length){sEmpty(tbody,'No data available.',cols);return}for(const item of items){const tr=document.createElement('tr');render(tr,item);tbody.appendChild(tr)}}
function sJson(value){try{return JSON.stringify(value)}catch(e){return '—'}}
function setBadge(summary){const health=sText(summary.health,'unknown'),count=Number(summary.high_critical_count||0);badge.textContent=health+' · '+count;healthChip.textContent='Health: '+health;highChip.textContent='High/Critical: '+count;const coverage=summary.latest_hourly&&summary.latest_hourly.coverage_pct!==undefined?summary.latest_hourly.coverage_pct+'%':'—';coverageChip.textContent='Coverage: '+coverage;document.getElementById('securityOverviewHealth').textContent=health;document.getElementById('securityOverviewHighCritical').textContent=String(count);document.getElementById('securityOverviewAssets').textContent=String(summary.enabled_asset_count||0);document.getElementById('securityOverviewCoverage').textContent=coverage}
async function refreshSecurityBadge(){try{const d=await api('/api/security/summary');setBadge(d)}catch(e){badge.textContent='unavailable'} }
async function loadOverview(){const [summary,findings]=await Promise.all([api('/api/security/summary'),api('/api/security/findings?limit=5&offset=0')]);setBadge(summary);const body=document.getElementById('securityOverviewFindings');sRows(body,findings.items||[],5,(tr,item)=>{sCell(tr,item.finding_id);sCell(tr,item.severity);sCell(tr,item.status);sCell(tr,item.category);sCell(tr,item.last_seen)})}
function renderPager(id,key,count,load){const wrap=document.getElementById(id);wrap.innerHTML='';const prev=document.createElement('button');prev.type='button';prev.className='soft-btn';prev.textContent='Previous';prev.disabled=offsets[key]===0;prev.onclick=()=>{offsets[key]=Math.max(0,offsets[key]-PAGE);load()};const label=document.createElement('span');label.textContent='Offset '+offsets[key]+' · '+count+' rows';const next=document.createElement('button');next.type='button';next.className='soft-btn';next.textContent='Next';next.disabled=count<PAGE||offsets[key]>=10000;next.onclick=()=>{offsets[key]=Math.min(10000,offsets[key]+PAGE);load()};wrap.append(prev,label,next)}
async function loadNetwork(){const d=await api('/api/security/network?limit='+PAGE+'&offset='+offsets.network),body=document.getElementById('securityNetworkRows');sRows(body,d.items||[],7,(tr,item)=>{sCell(tr,item.observed_at);sCell(tr,item.asset_id);sCell(tr,item.collector);sCell(tr,item.metric);sCell(tr,item.status);sCell(tr,sJson(item.value)+(item.unit?' '+item.unit:''));sCell(tr,item.evidence_ref)});renderPager('securityNetworkPager','network',(d.items||[]).length,loadNetwork)}
async function loadFindings(){const d=await api('/api/security/findings?limit='+PAGE+'&offset='+offsets.findings),body=document.getElementById('securityFindingRows');sRows(body,d.items||[],6,(tr,item)=>{tr.className='clickable';sCell(tr,item.finding_id);sCell(tr,item.severity);sCell(tr,item.status);sCell(tr,item.category);sCell(tr,(item.asset_refs||[]).join(', '));sCell(tr,item.last_seen);tr.onclick=()=>{document.getElementById('securityFindingDetail').textContent=JSON.stringify(item,null,2)}});renderPager('securityFindingPager','findings',(d.items||[]).length,loadFindings)}
async function loadEvents(){const d=await api('/api/security/events?limit='+PAGE+'&offset='+offsets.events),body=document.getElementById('securityEventRows');sRows(body,d.items||[],7,(tr,item)=>{sCell(tr,item.observed_at);sCell(tr,item.source_id);sCell(tr,item.source_type);sCell(tr,item.severity);sCell(tr,item.category);sCell(tr,item.parser_version);sCell(tr,item.evidence_ref)});renderPager('securityEventPager','events',(d.items||[]).length,loadEvents)}
async function loadAssets(){const d=await api('/api/security/assets'),body=document.getElementById('securityAssetRows');sRows(body,d.items||[],7,(tr,item)=>{sCell(tr,item.asset_id);sCell(tr,item.role);sCell(tr,item.enabled?'yes':'no');sCell(tr,item.data_class);sCell(tr,(item.collector_capabilities||[]).join(', '));sCell(tr,item.observed_state?.last_status);sCell(tr,item.observed_state?.last_observed_at)})}
async function loadReports(){const d=await api('/api/security/reports?limit='+PAGE+'&offset='+offsets.reports),body=document.getElementById('securityReportRows');sRows(body,d.items||[],6,(tr,item)=>{sCell(tr,item.archive_id);sCell(tr,item.period_kind+' · '+item.period_key);sCell(tr,item.status);sCell(tr,item.attempt);sCell(tr,item.updated_at);sCell(tr,item.manifest_sha256)});renderPager('securityReportPager','reports',(d.items||[]).length,loadReports)}
function adminKV(grid,key,value){const box=document.createElement('div');box.className='security-kv';const b=document.createElement('b');b.textContent=key;const span=document.createElement('span');span.textContent=typeof value==='object'?JSON.stringify(value):sText(value);box.append(b,span);grid.appendChild(box)}
async function loadAdmin(){const grid=document.getElementById('securityAdminGrid');grid.innerHTML='';try{const d=await api('/api/security/admin');for(const key of ['config_state','database_available','schema_version_db','enabled','allow_real_network','asset_count','secret_boundary_configured','read_only_ui','mutations_exposed','autonomous_remediation','autonomous_pcap','passive_sensors_optional'])adminKV(grid,key,d[key]);adminKV(grid,'policy',d.policy||{})}catch(e){adminKV(grid,'Administration',e.message)}}
const loaders={overview:loadOverview,network:loadNetwork,findings:loadFindings,events:loadEvents,assets:loadAssets,reports:loadReports,admin:loadAdmin};
async function loadActive(){try{await loaders[activeTab]()}catch(e){showToast('Security Analyst: '+e.message)}}
function schedulePoll(){if(pollHandle){clearInterval(pollHandle);pollHandle=null}if(!securityOpen||document.visibilityState!=='visible')return;pollHandle=setInterval(()=>{if(securityOpen&&document.visibilityState==='visible')refreshSecurityBadge()},30000)}
function activateTab(name){activeTab=name;for(const b of document.querySelectorAll('[data-security-tab]'))b.classList.toggle('active',b.dataset.securityTab===name);for(const v of document.querySelectorAll('[data-security-view]'))v.classList.toggle('active',v.dataset.securityView===name);loadActive()}
function openSecurity(){securityOpen=true;previousTitle=document.getElementById('conversationName').textContent;document.body.classList.add('security-analyst-open');surface.classList.add('open');document.getElementById('conversationName').textContent='Security Analyst';document.getElementById('securityAdminTab').classList.toggle('hidden',state.session?.role!=='admin');refreshSecurityBadge();loadActive();schedulePoll();if(window.innerWidth<=760)setSidebarCollapsed(true)}
function closeSecurity(){if(!securityOpen)return;securityOpen=false;surface.classList.remove('open');document.body.classList.remove('security-analyst-open');document.getElementById('conversationName').textContent=previousTitle||'New chat';schedulePoll()}
document.getElementById('securityAnalystBtn').onclick=openSecurity;document.getElementById('securityAnalystClose').onclick=closeSecurity;for(const b of document.querySelectorAll('[data-security-tab]'))b.onclick=()=>activateTab(b.dataset.securityTab);document.addEventListener('visibilitychange',schedulePoll);for(const id of ['newChatBtn','historyList','pinnedList','projectsList','archivedChatsBtn']){const e=document.getElementById(id);if(e)e.addEventListener('click',closeSecurity)}document.getElementById('loginBtn').addEventListener('click',()=>setTimeout(refreshSecurityBadge,800));setTimeout(refreshSecurityBadge,1000);
})();
'''
html = _replace_once(
    html,
    "</body>",
    f"<script>{security_js}</script></body>",
    "security-analyst-js",
)

WORKSPACE_HTML_V13 = html


# Later security overlays are version-independent builders.  They intentionally
# avoid importing V15 during module import so V14 can consume V13 without a cycle.
SOC_SECURITY_CSS = r'''
.security-soc-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.security-soc-section{margin-top:14px}.security-soc-section h3{font-size:13px;margin:0 0 8px}.security-soc-note{color:#858a94;font-size:10px;line-height:1.45;margin:0 0 8px}.security-truth-state{display:inline-block;border:1px solid #3c414a;border-radius:999px;padding:2px 7px;font-size:9px;font-weight:700;white-space:nowrap}.security-truth-state.verified{border-color:#315a46;color:#b8dbc9}.security-truth-state.inference{border-color:#5a4930;color:#e3c895}.security-truth-state.unknown{border-color:#454954;color:#b7bbc4}@media(max-width:900px){.security-soc-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:640px){.security-soc-grid{grid-template-columns:1fr}}
'''

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

SECURITY_BOUNDARY_CSS = r'''
.security-boundary-intro{border:1px solid #4b4232;background:#1b1710;border-radius:12px;padding:11px 12px;color:#ddc99f;font-size:11px;line-height:1.5;margin-bottom:12px}.security-boundary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.security-boundary-card{border:1px solid #343840;background:#111317;border-radius:11px;padding:11px}.security-boundary-card b{display:block;font-size:11px;margin-bottom:6px}.security-boundary-state{display:inline-block;border:1px solid #5a4930;border-radius:999px;padding:2px 7px;color:#e3c895;font-size:9px;font-weight:750;letter-spacing:.03em}.security-boundary-card p{margin:7px 0 0;color:#858a94;font-size:10px;line-height:1.45}@media(max-width:760px){.security-boundary-grid{grid-template-columns:1fr}}
'''

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


def build_security_v2(base_html: str) -> str:
    html = base_html
    html = _replace_once(html, "</style>", SOC_SECURITY_CSS + "</style>", "security-soc-css")
    html = _replace_once(
        html,
        '        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
        '        <button class="security-tab" data-security-tab="soc" id="securitySocTab" type="button">SOC</button>\n        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
        "security-soc-tab",
    )
    html = _replace_once(
        html,
        '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
        SOC_SECURITY_MARKUP + '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
        "security-soc-view",
    )
    html = _replace_once(html, "</body>", "<script>" + SOC_SECURITY_JS + "</script>\n</body>", "security-soc-js")
    return html


def build_security_v3(base_html: str) -> str:
    html = build_security_v2(base_html)
    html = _replace_once(html, "</style>", SECURITY_BOUNDARY_CSS + "</style>", "security-boundary-css")
    html = _replace_once(
        html,
        '        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
        '        <button class="security-tab" data-security-tab="boundaries" id="securityBoundaryTab" type="button">Boundaries</button>\n        <button class="security-tab hidden" data-security-tab="configuration" id="securityConfigTab" type="button">Configuration</button>',
        "security-boundary-tab",
    )
    html = _replace_once(
        html,
        '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
        SECURITY_BOUNDARY_MARKUP + '      <div class="security-view" data-security-view="configuration" id="securityConfigView">',
        "security-boundary-view",
    )
    return html


def _ensure_compatibility_html() -> None:
    if "WORKSPACE_HTML_SECURITY_V2" in globals() and "WORKSPACE_HTML_SECURITY_V3" in globals():
        return
    from .workspace_frontend_v15 import WORKSPACE_HTML_V15

    globals()["WORKSPACE_HTML_SECURITY_V2"] = build_security_v2(WORKSPACE_HTML_V15)
    globals()["WORKSPACE_HTML_SECURITY_V3"] = build_security_v3(WORKSPACE_HTML_V15)


def __getattr__(name: str):
    if name in {"WORKSPACE_HTML_SECURITY_V2", "WORKSPACE_HTML_SECURITY_V3"}:
        _ensure_compatibility_html()
        return globals()[name]
    raise AttributeError(name)

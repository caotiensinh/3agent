from __future__ import annotations

import argparse
import hmac
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .security_monitoring.demo import create_demo_environment
from .security_monitoring.locking import MonitoringRunAlreadyLocked
from .security_monitoring.service import SecurityMonitoringService
from .security_monitoring.ui_config import (
    SecurityMonitoringUIConfigManager,
    default_config_path,
    safe_default_payload,
)

MAX_REQUEST_BYTES = 4096
_LOCAL_HOSTS = {"127.0.0.1", "localhost"}

_PAGE = r'''<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>WorkSpace Security Console</title>
  <style nonce="__CSP_NONCE__">
    :root { font-family: system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color-scheme: dark; }
    * { box-sizing: border-box; }
    body { margin:0; background:#0b1220; color:#e5e7eb; }
    main { max-width:1280px; margin:0 auto; padding:24px 18px 48px; }
    h1 { margin:0 0 4px; font-size:28px; }
    h2 { margin:0 0 8px; font-size:20px; }
    .muted { color:#94a3b8; }
    .banner { margin:16px 0; border:1px solid #0ea5e9; border-radius:10px; padding:12px; background:#082f49; }
    .tabs { display:flex; gap:8px; flex-wrap:wrap; margin:18px 0; position:sticky; top:0; padding:10px 0; background:#0b1220; z-index:2; }
    .tabs button { margin:0; background:#1e293b; color:#e2e8f0; }
    .tabs button.active { background:#0369a1; }
    .panel { display:none; }
    .panel.active { display:block; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin-top:12px; }
    .card { border:1px solid #334155; border-radius:12px; padding:14px; background:#111827; }
    .label { color:#94a3b8; font-size:12px; }
    .value { margin-top:5px; font-size:21px; font-weight:700; overflow-wrap:anywhere; }
    .good { color:#86efac; } .bad { color:#fca5a5; } .warn { color:#fde68a; }
    button { border:0; border-radius:8px; padding:10px 14px; font-weight:700; cursor:pointer; }
    button:disabled { opacity:.45; cursor:not-allowed; }
    .primary { background:#0369a1; color:white; }
    .safe { background:#166534; color:white; }
    pre { white-space:pre-wrap; overflow-wrap:anywhere; border:1px solid #334155; border-radius:10px; padding:12px; background:#020617; }
    table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
    th,td { border-bottom:1px solid #334155; text-align:left; padding:9px 7px; vertical-align:top; }
    th { color:#94a3b8; font-weight:600; }
    .table-wrap { overflow:auto; max-height:420px; }
    ul { padding-left:20px; }
    .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
  </style>
</head>
<body>
<main>
  <h1>WorkSpace Security Console</h1>
  <div class="muted">ローカル専用 Security / Network / Monitoring / Analyst Console</div>
  <div id="demo-banner" class="banner" hidden>DEMO MODE — 合成データのみ。実ネットワーク、Packet Capture、Remediation は実行しません。</div>

  <nav class="tabs">
    <button class="tab active" data-panel="overview">Overview</button>
    <button class="tab" data-panel="analyst">Analyst Workspace</button>
    <button class="tab" data-panel="capability-center">Capability Center</button>
    <button class="tab" data-panel="operations">Operations</button>
    <button class="tab" data-panel="readiness-panel">Readiness</button>
  </nav>

  <section id="overview" class="panel active">
    <div class="grid">
      <section class="card"><div class="label">監視</div><div id="enabled" class="value">読込中</div></section>
      <section class="card"><div class="label">実ネットワーク読取</div><div id="network" class="value">読込中</div></section>
      <section class="card"><div class="label">準備状況</div><div id="ready" class="value">読込中</div></section>
      <section class="card"><div class="label">有効アセット</div><div id="assets" class="value">-</div></section>
      <section class="card"><div class="label">Open findings</div><div id="evidence-open" class="value">-</div></section>
      <section class="card"><div class="label">High / Critical</div><div id="evidence-high" class="value">-</div></section>
      <section class="card"><div class="label">Correlation graphs</div><div id="operator-graphs" class="value">-</div></section>
      <section class="card"><div class="label">Flow events</div><div id="operator-flows" class="value">-</div></section>
      <section class="card"><div class="label">Timeline entries</div><div id="operator-timeline" class="value">-</div></section>
    </div>

    <section class="card" style="margin-top:14px">
      <h2>Asset Intelligence</h2>
      <p class="muted">承認済み設定から集計値のみを表示します。アセットID、管理ホスト、資格情報参照、TCPポート値は表示しません。</p>
      <pre id="asset-intelligence">Asset Intelligence を読み込んでいます...</pre>
    </section>
    <section class="card" style="margin-top:14px">
      <h2>Evidence / Result History</h2>
      <p class="muted">監視DBの直近最大100件/ストリームを集計値だけで表示します。アセットID、ソースID、Finding ID、Evidence参照、Bundle参照、RAW値は表示しません。</p>
      <pre id="evidence-summary">Evidence summary を読み込んでいます...</pre>
    </section>
    <section class="card" style="margin-top:14px">
      <h2>Incident Posture</h2>
      <p class="muted">Finding ID、Asset参照、Evidence参照、Rule ID、Category値は表示しません。</p>
      <pre id="incident-posture">Incident posture を読み込んでいます...</pre>
    </section>
    <section class="card" style="margin-top:14px">
      <h2>Operator Posture</h2>
      <p class="muted">Risk・Asset Health・Correlation・Flow・Timeline を固定集計値で統合します。正確な時刻は表示しません。</p>
      <pre id="operator-posture">Operator posture を読み込んでいます...</pre>
    </section>
  </section>

  <section id="analyst" class="panel">
    <section class="card">
      <h2>Analyst Workspace — Read Only</h2>
      <p class="muted">Backend の query-only read model を最大50件/streamで表示します。Raw Asset ID / IP / Hostname / Credential / Evidence Ref / Event ID / Finding ID / Rule ID はブラウザへ返しません。</p>
      <div class="grid">
        <section class="card"><div class="label">Data state</div><div id="analyst-state" class="value">-</div></section>
        <section class="card"><div class="label">Assets</div><div id="analyst-assets-count" class="value">-</div></section>
        <section class="card"><div class="label">Network observations</div><div id="analyst-network-count" class="value">-</div></section>
        <section class="card"><div class="label">Events</div><div id="analyst-events-count" class="value">-</div></section>
        <section class="card"><div class="label">Findings</div><div id="analyst-findings-count" class="value">-</div></section>
      </div>
    </section>

    <section class="card" style="margin-top:14px"><h2>Assets</h2><div class="table-wrap"><table id="assets-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Network Observations</h2><div class="table-wrap"><table id="network-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Security Events</h2><div class="table-wrap"><table id="events-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Findings</h2><div class="table-wrap"><table id="findings-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Reports</h2><div class="table-wrap"><table id="reports-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Admin / Safety Status</h2><pre id="admin-status">読込中...</pre></section>
  </section>

  <section id="capability-center" class="panel">
    <section class="card">
      <h2>Capability Center — Safe Activation Status</h2>
      <p class="muted">Backend capability の状態を表示するだけです。ACTIVE / READY はブラウザに新しい実行権限を与えません。Packet Capture、Remediation、Shell、任意Target Scan、Credential入力は無効のままです。</p>
      <div class="grid">
        <section class="card"><div class="label">ACTIVE</div><div id="cap-active" class="value">-</div></section>
        <section class="card"><div class="label">READY</div><div id="cap-ready" class="value">-</div></section>
        <section class="card"><div class="label">GATED</div><div id="cap-gated" class="value">-</div></section>
        <section class="card"><div class="label">DISABLED / NOT CONFIGURED</div><div id="cap-disabled" class="value">-</div></section>
      </div>
    </section>
    <section class="card" style="margin-top:14px"><h2>Read Surfaces</h2><div class="table-wrap"><table id="cap-read-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Local Operations</h2><p class="muted">READY でも実行時には既存の CSRF / readiness / policy / explicit confirmation gate が必要です。</p><div class="table-wrap"><table id="cap-operations-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Collector Capabilities</h2><div class="table-wrap"><table id="cap-collectors-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Restricted Surfaces</h2><div class="table-wrap"><table id="cap-restricted-table"></table></div></section>
    <section class="card" style="margin-top:14px"><h2>Matrix Authority</h2><pre id="cap-authority">読込中...</pre></section>
  </section>

  <section id="operations" class="panel">
    <section class="card">
      <h2>Local setup</h2>
      <p class="muted">Initialize はローカルSQLite schemaと承認済みinventoryだけを同期します。ネットワーク通信は発生しません。</p>
      <div class="actions"><button id="initialize" class="safe">ローカル監視DBを初期化</button></div>
      <pre id="initialize-result">未実行</pre>
    </section>
    <section class="card" style="margin-top:14px">
      <h2>Read-only monitoring</h2>
      <p class="muted">設定ファイルは起動時に固定されます。ブラウザから path / target / credential / shell を指定することはできません。</p>
      <div class="actions"><button id="run" class="primary" disabled>読み取り専用監視を実行</button></div>
      <pre id="result">準備状況を確認しています...</pre>
    </section>
  </section>

  <section id="readiness-panel" class="panel">
    <section class="card"><h2>Readiness</h2><ul id="issues"></ul><pre id="readiness-json"></pre></section>
  </section>
</main>
<script nonce="__CSP_NONCE__">
const csrf = "__CSRF_TOKEN__";
const demoMode = __DEMO_MODE__;
const byId = (id) => document.getElementById(id);
let readiness = null;

function setState(el, value) {
  el.textContent = value ? "有効" : "無効";
  el.className = "value " + (value ? "good" : "bad");
}
function text(value) { return value === null || value === undefined ? "-" : String(value); }
function renderTable(id, columns, rows) {
  const table = byId(id); table.replaceChildren();
  const thead = document.createElement("thead"); const trh = document.createElement("tr");
  for (const [key,label] of columns) { const th=document.createElement("th"); th.textContent=label; trh.appendChild(th); }
  thead.appendChild(trh); table.appendChild(thead);
  const tbody=document.createElement("tbody");
  const safeRows=Array.isArray(rows)?rows:[];
  if (!safeRows.length) {
    const tr=document.createElement("tr"); const td=document.createElement("td");
    td.colSpan=columns.length; td.textContent="No data"; tr.appendChild(td); tbody.appendChild(tr);
  } else {
    for (const row of safeRows) {
      const tr=document.createElement("tr");
      for (const [key] of columns) { const td=document.createElement("td"); const v=row[key]; td.textContent=Array.isArray(v)?v.join(", "):text(v); tr.appendChild(td); }
      tbody.appendChild(tr);
    }
  }
  table.appendChild(tbody);
}
function activatePanel(name) {
  document.querySelectorAll(".panel").forEach(el => el.classList.toggle("active", el.id===name));
  document.querySelectorAll(".tab").forEach(el => el.classList.toggle("active", el.dataset.panel===name));
}
function renderCapabilityCenter(matrix) {
  const readSurfaces=matrix.read_surfaces||[];
  const operations=matrix.local_operations||[];
  const collectors=matrix.collector_capabilities||[];
  const restricted=matrix.restricted_surfaces||[];
  const all=[...readSurfaces,...operations,...collectors,...restricted];
  const count=(state)=>all.filter(item=>item && item.state===state).length;
  byId("cap-active").textContent=text(count("active"));
  byId("cap-ready").textContent=text(count("ready"));
  byId("cap-gated").textContent=text(count("gated"));
  byId("cap-disabled").textContent=text(count("disabled")+count("not_configured"));
  for (const id of ["cap-active","cap-ready","cap-gated","cap-disabled"]) { byId(id).className="value"; }
  renderTable("cap-read-table",[["name","Capability"],["state","State"],["reason_code","Reason"]],readSurfaces);
  renderTable("cap-operations-table",[["name","Operation"],["state","State"],["reason_code","Reason"],["user_confirmation_required","Confirmation"]],operations);
  renderTable("cap-collectors-table",[["name","Collector"],["state","State"],["reason_code","Reason"],["configured_asset_count","Approved assets"],["user_confirmation_required","Confirmation"]],collectors);
  renderTable("cap-restricted-table",[["name","Restricted surface"],["state","State"],["reason_code","Reason"]],restricted);
  byId("cap-authority").textContent=JSON.stringify(matrix.authority||{},null,2);
}
function markValueError(ids) {
  for (const id of ids) { byId(id).textContent="ERROR"; byId(id).className="value bad"; }
}
function surfaceUnavailable(label) { return "Backend surface unavailable: "+label; }
function settledPayload(result) {
  if (!result || result.status!=="fulfilled" || !result.value || typeof result.value!=="object" || Array.isArray(result.value)) return null;
  return result.value;
}
function clearReadinessSurface(message) {
  readiness=null;
  markValueError(["ready"]);
  byId("readiness-json").textContent=message;
  const list=byId("issues"); list.replaceChildren();
  const li=document.createElement("li"); li.textContent=message; list.appendChild(li);
  byId("run").disabled=true;
  byId("result").textContent=message;
}
function clearAnalystSurface(message) {
  markValueError(["analyst-state","analyst-assets-count","analyst-network-count","analyst-events-count","analyst-findings-count","cap-active","cap-ready","cap-gated","cap-disabled"]);
  renderTable("assets-table",[["alias","Asset"],["enabled","Enabled"],["data_class","Data class"],["collector_capabilities","Collectors"],["last_status","Status"],["recency","Recency"]],[]);
  renderTable("network-table",[["asset","Asset"],["collector","Collector"],["status","Status"],["recency","Recency"],["has_value","Value"],["has_evidence","Evidence"]],[]);
  renderTable("events-table",[["source_type","Source"],["stage","Stage"],["severity","Severity"],["recency","Recency"],["has_evidence","Evidence"]],[]);
  renderTable("findings-table",[["severity","Severity"],["status","Status"],["asset_link_count","Assets"],["evidence_link_count","Evidence"],["recency","Recency"]],[]);
  renderTable("reports-table",[["period_kind","Period"],["status","Status"],["recency","Recency"]],[]);
  renderTable("cap-read-table",[["name","Capability"],["state","State"],["reason_code","Reason"]],[]);
  renderTable("cap-operations-table",[["name","Operation"],["state","State"],["reason_code","Reason"],["user_confirmation_required","Confirmation"]],[]);
  renderTable("cap-collectors-table",[["name","Collector"],["state","State"],["reason_code","Reason"],["configured_asset_count","Approved assets"],["user_confirmation_required","Confirmation"]],[]);
  renderTable("cap-restricted-table",[["name","Restricted surface"],["state","State"],["reason_code","Reason"]],[]);
  byId("admin-status").textContent=message;
  byId("cap-authority").textContent=message;
}
document.querySelectorAll(".tab").forEach(el => el.addEventListener("click", () => activatePanel(el.dataset.panel)));

async function jsonGet(path) {
  const response=await fetch(path,{cache:"no-store"}); const payload=await response.json();
  if (!response.ok) throw new Error(payload.reason_code || path); return payload;
}
async function refresh() {
  const [summaryResult, readyResult, assetResult, evidenceResult, incidentResult, operatorResult, analystResult] = await Promise.allSettled([
    jsonGet("/api/v1/security/monitoring/summary"),
    jsonGet("/api/v1/security/monitoring/readiness"),
    jsonGet("/api/v1/security/monitoring/asset-intelligence"),
    jsonGet("/api/v1/security/monitoring/evidence-summary"),
    jsonGet("/api/v1/security/monitoring/incident-posture"),
    jsonGet("/api/v1/security/monitoring/operator-posture"),
    jsonGet("/api/v1/security/monitoring/analyst-snapshot")
  ]);

  const summary=settledPayload(summaryResult);
  if (summary) {
    setState(byId("enabled"),summary.enabled===true); setState(byId("network"),summary.allow_real_network===true);
    byId("assets").textContent=text(summary.enabled_asset_count||0); byId("assets").className="value";
  } else {
    markValueError(["enabled","network","assets"]);
  }

  const ready=settledPayload(readyResult);
  if (ready) {
    readiness=ready;
    byId("ready").textContent=ready.ready?"READY":"BLOCKED"; byId("ready").className="value "+(ready.ready?"good":"bad");
    byId("readiness-json").textContent=JSON.stringify(ready,null,2);
    const list=byId("issues"); list.replaceChildren();
    for (const issue of ready.issues||[]) { const li=document.createElement("li"); li.textContent=(issue.code||"UNKNOWN")+": "+(issue.message||""); list.appendChild(li); }
    if (!(ready.issues||[]).length) { const li=document.createElement("li"); li.textContent="No blocking issues"; list.appendChild(li); }
    byId("run").disabled=!ready.ready || demoMode;
    byId("result").textContent=demoMode ? "DEMO MODE: 実ネットワーク監視は無効です。Analyst Workspace で合成データを確認してください。" : (ready.ready?"実行可能":"Readiness BLOCKED");
  } else {
    clearReadinessSurface(surfaceUnavailable("readiness"));
  }

  const asset=settledPayload(assetResult);
  byId("asset-intelligence").textContent=asset ? JSON.stringify(asset,null,2) : surfaceUnavailable("asset-intelligence");

  const evidence=settledPayload(evidenceResult);
  if (evidence) {
    byId("evidence-open").textContent=text(evidence.open_finding_count||0); byId("evidence-open").className="value";
    byId("evidence-high").textContent=text(evidence.high_critical_count||0); byId("evidence-high").className="value";
    byId("evidence-summary").textContent=JSON.stringify(evidence,null,2);
  } else {
    markValueError(["evidence-open","evidence-high"]);
    byId("evidence-summary").textContent=surfaceUnavailable("evidence-summary");
  }

  const incident=settledPayload(incidentResult);
  byId("incident-posture").textContent=incident ? JSON.stringify(incident,null,2) : surfaceUnavailable("incident-posture");

  const operator=settledPayload(operatorResult);
  if (operator) {
    const corr=operator.correlation||{}, flow=operator.flow||{}, timeline=operator.timeline||{};
    byId("operator-graphs").textContent=text(corr.incident_graph_count||0); byId("operator-graphs").className="value";
    byId("operator-flows").textContent=text(flow.flow_event_count||0); byId("operator-flows").className="value";
    byId("operator-timeline").textContent=text(timeline.entry_count||0); byId("operator-timeline").className="value";
    byId("operator-posture").textContent=JSON.stringify(operator,null,2);
  } else {
    markValueError(["operator-graphs","operator-flows","operator-timeline"]);
    byId("operator-posture").textContent=surfaceUnavailable("operator-posture");
  }

  const analyst=settledPayload(analystResult);
  if (analyst) {
    byId("analyst-state").textContent=text(analyst.data_state); byId("analyst-state").className="value";
    byId("analyst-assets-count").textContent=text((analyst.assets||[]).length); byId("analyst-assets-count").className="value";
    byId("analyst-network-count").textContent=text((analyst.network||[]).length); byId("analyst-network-count").className="value";
    byId("analyst-events-count").textContent=text((analyst.events||[]).length); byId("analyst-events-count").className="value";
    byId("analyst-findings-count").textContent=text((analyst.findings||[]).length); byId("analyst-findings-count").className="value";
    renderTable("assets-table",[["alias","Asset"],["enabled","Enabled"],["data_class","Data class"],["collector_capabilities","Collectors"],["last_status","Status"],["recency","Recency"]],analyst.assets);
    renderTable("network-table",[["asset","Asset"],["collector","Collector"],["status","Status"],["recency","Recency"],["has_value","Value"],["has_evidence","Evidence"]],analyst.network);
    renderTable("events-table",[["source_type","Source"],["stage","Stage"],["severity","Severity"],["recency","Recency"],["has_evidence","Evidence"]],analyst.events);
    renderTable("findings-table",[["severity","Severity"],["status","Status"],["asset_link_count","Assets"],["evidence_link_count","Evidence"],["recency","Recency"]],analyst.findings);
    renderTable("reports-table",[["period_kind","Period"],["status","Status"],["recency","Recency"]],analyst.reports);
    const admin=analyst.admin||{};
    const matrix=admin.capability_matrix||{};
    renderCapabilityCenter(matrix);
    byId("admin-status").textContent=JSON.stringify({admin:admin,authority:analyst.authority},null,2);
  } else {
    clearAnalystSurface(surfaceUnavailable("analyst-snapshot"));
  }

  byId("demo-banner").hidden=!demoMode;
}
async function postExact(path,payload,target) {
  target.textContent="実行中...";
  try {
    const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json","X-Workspace-CSRF":csrf},body:JSON.stringify(payload),cache:"no-store"});
    const data=await response.json();
    target.textContent=JSON.stringify(data,null,2);
  } catch {
    target.textContent="Backend operation unavailable";
  }
  await refresh();
}
byId("run").addEventListener("click",async()=>{ if(!readiness?.ready||demoMode)return; if(!window.confirm("承認済みアセットに対して読み取り専用監視を実行しますか？"))return; await postExact("/api/v1/security/monitoring/run-hourly",{confirm_readonly:true},byId("result")); });
byId("initialize").addEventListener("click",async()=>{ if(!window.confirm("ローカル監視DBを初期化し、承認済みinventoryを同期しますか？"))return; await postExact("/api/v1/security/monitoring/initialize",{confirm_initialize:true},byId("initialize-result")); });
refresh();
</script>
</body>
</html>'''


def validate_loopback_host(host: str) -> str:
    normalized = str(host or "").strip().lower()
    if normalized not in _LOCAL_HOSTS:
        raise ValueError("SECURITY_CONSOLE_LOOPBACK_ONLY")
    return normalized


def _request_host_is_loopback(value: str | None) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    if raw.startswith("["):
        return False
    host = raw.rsplit(":", 1)[0] if ":" in raw else raw
    return host in _LOCAL_HOSTS


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], service: SecurityMonitoringService, *, csrf_token: str, csp_nonce: str, demo_mode: bool) -> None:
        super().__init__(address, _Handler)
        self.service = service
        self.csrf_token = csrf_token
        self.csp_nonce = csp_nonce
        self.demo_mode = demo_mode


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: object) -> None:
        return

    def _headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", f"default-src 'none'; style-src 'nonce-{self.server.csp_nonce}'; script-src 'nonce-{self.server.csp_nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")

    def _json(self, status: int, payload: dict[str, object]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _html(self) -> None:
        page = (
            _PAGE.replace("__CSRF_TOKEN__", self.server.csrf_token)
            .replace("__CSP_NONCE__", self.server.csp_nonce)
            .replace("__DEMO_MODE__", "true" if self.server.demo_mode else "false")
        )
        raw = page.encode("utf-8")
        self.send_response(200)
        self._headers("text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _host_ok(self) -> bool:
        if _request_host_is_loopback(self.headers.get("Host")):
            return True
        self._json(421, {"status": "blocked", "reason_code": "LOOPBACK_HOST_REQUIRED"})
        return False

    def _body(self) -> dict[str, object] | None:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._json(400, {"status": "blocked", "reason_code": "INVALID_CONTENT_LENGTH"})
            return None
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._json(400, {"status": "blocked", "reason_code": "INVALID_REQUEST_SIZE"})
            return None
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"status": "blocked", "reason_code": "INVALID_JSON"})
            return None
        if not isinstance(payload, dict):
            self._json(400, {"status": "blocked", "reason_code": "JSON_OBJECT_REQUIRED"})
            return None
        return payload

    def _csrf_ok(self) -> bool:
        supplied = str(self.headers.get("X-Workspace-CSRF") or "")
        if supplied and hmac.compare_digest(supplied, self.server.csrf_token):
            return True
        self._json(403, {"status": "blocked", "reason_code": "CSRF_TOKEN_REQUIRED"})
        return False

    def do_GET(self) -> None:
        if not self._host_ok():
            return
        path = urlsplit(self.path).path
        try:
            if path == "/":
                self._html()
                return
            if path == "/api/v1/health":
                self._json(
                    200,
                    {
                        "status": "ok",
                        "service": "WorkSpace Security Console",
                        "local_only": True,
                        "write_authority": False,
                        "bounded_local_initialize": True,
                        "demo_mode": self.server.demo_mode,
                    },
                )
                return
            if path == "/api/v1/security/monitoring/summary":
                self._json(200, self.server.service.summary())
                return
            if path == "/api/v1/security/monitoring/readiness":
                self._json(200, self.server.service.readiness())
                return
            if path == "/api/v1/security/monitoring/asset-intelligence":
                self._json(200, self.server.service.asset_intelligence())
                return
            if path == "/api/v1/security/monitoring/evidence-summary":
                self._json(200, self.server.service.evidence_summary())
                return
            if path == "/api/v1/security/monitoring/incident-posture":
                self._json(200, self.server.service.incident_posture())
                return
            if path == "/api/v1/security/monitoring/operator-posture":
                self._json(200, self.server.service.operator_posture())
                return
            if path == "/api/v1/security/monitoring/analyst-snapshot":
                self._json(200, self.server.service.analyst_snapshot())
                return
            self._json(404, {"status": "not_found", "reason_code": "ENDPOINT_NOT_FOUND"})
        except Exception as exc:
            self._json(500, {"status": "error", "reason_code": type(exc).__name__})

    def do_POST(self) -> None:
        if not self._host_ok() or not self._csrf_ok():
            return
        path = urlsplit(self.path).path
        if path not in {
            "/api/v1/security/monitoring/run-hourly",
            "/api/v1/security/monitoring/initialize",
        }:
            self._json(404, {"status": "not_found", "reason_code": "ENDPOINT_NOT_FOUND"})
            return
        payload = self._body()
        if payload is None:
            return
        if path.endswith("/run-hourly"):
            if set(payload) != {"confirm_readonly"}:
                self._json(400, {"status": "blocked", "reason_code": "UNSUPPORTED_REQUEST_FIELDS"})
                return
            if payload.get("confirm_readonly") is not True:
                self._json(409, {"status": "blocked", "reason_code": "USER_CONFIRMATION_REQUIRED"})
                return
            if self.server.demo_mode:
                self._json(409, {"status": "blocked", "reason_code": "DEMO_MODE_NETWORK_EXECUTION_DISABLED"})
                return
            try:
                result = self.server.service.run_hourly(execute_readonly=True)
            except MonitoringRunAlreadyLocked:
                self._json(409, {"status": "blocked", "reason_code": "MONITORING_RUN_ALREADY_LOCKED"})
                return
            except RuntimeError as exc:
                self._json(409, {"status": "blocked", "reason_code": str(exc)[:256]})
                return
            self._json(200, result)
            return

        if set(payload) != {"confirm_initialize"}:
            self._json(400, {"status": "blocked", "reason_code": "UNSUPPORTED_REQUEST_FIELDS"})
            return
        if payload.get("confirm_initialize") is not True:
            self._json(409, {"status": "blocked", "reason_code": "USER_CONFIRMATION_REQUIRED"})
            return
        try:
            result = self.server.service.initialize()
        except RuntimeError as exc:
            self._json(409, {"status": "blocked", "reason_code": str(exc)[:256]})
            return
        self._json(200, result)


def build_server(
    host: str,
    port: int,
    service: SecurityMonitoringService,
    *,
    csrf_token: str | None = None,
    csp_nonce: str | None = None,
    demo_mode: bool = False,
) -> _Server:
    bind = validate_loopback_host(host)
    return _Server(
        (bind, int(port)),
        service,
        csrf_token=csrf_token or secrets.token_hex(32),
        csp_nonce=csp_nonce or secrets.token_hex(16),
        demo_mode=demo_mode,
    )


def _ensure_safe_default(path: Path) -> None:
    if path.is_file():
        return
    manager = SecurityMonitoringUIConfigManager(path.resolve(), path_source="workspace_default")
    manager.save(safe_default_payload(path.resolve()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WorkSpace local-only security monitoring console"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Monitoring config path. Defaults to the portable WorkSpace user config.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Launch isolated synthetic demo data with all real-network execution disabled.",
    )
    args = parser.parse_args(argv)
    host = validate_loopback_host(args.host)
    if args.demo:
        config_path = create_demo_environment()
    else:
        config_path = (args.config or default_config_path()).expanduser().resolve()
        _ensure_safe_default(config_path)
    service = SecurityMonitoringService(config_path)
    server = build_server(host, args.port, service, demo_mode=args.demo)
    print(f"WorkSpace Security Console: http://{host}:{server.server_port}/")
    print(f"Monitoring config: {config_path}")
    if args.demo:
        print("DEMO MODE: synthetic data only; real network execution is disabled")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
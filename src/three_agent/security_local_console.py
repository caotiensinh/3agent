from __future__ import annotations

import argparse
import hmac
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .security_monitoring.locking import MonitoringRunAlreadyLocked
from .security_monitoring.service import SecurityMonitoringService

MAX_REQUEST_BYTES = 4096
_LOCAL_HOSTS = {"127.0.0.1", "localhost"}

_PAGE = """<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>WorkSpace Security Console</title>
  <style nonce="__CSP_NONCE__">
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color-scheme: light dark; }
    body { margin: 0; background: #111827; color: #e5e7eb; }
    main { max-width: 1080px; margin: 0 auto; padding: 28px 20px 48px; }
    h1 { margin: 0 0 6px; font-size: 28px; }
    .muted { color: #9ca3af; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); gap: 14px; margin-top: 20px; }
    .card { border: 1px solid #374151; border-radius: 12px; padding: 16px; background: #1f2937; }
    .label { color: #9ca3af; font-size: 13px; }
    .value { margin-top: 6px; font-size: 22px; font-weight: 700; overflow-wrap: anywhere; }
    .good { color: #86efac; } .bad { color: #fca5a5; } .warn { color: #fde68a; }
    button { margin-top: 18px; border: 0; border-radius: 9px; padding: 11px 15px; font-weight: 700; cursor: pointer; }
    button:disabled { opacity: .45; cursor: not-allowed; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; border: 1px solid #374151; border-radius: 10px; padding: 14px; background: #111827; }
    ul { padding-left: 20px; }
  </style>
</head>
<body>
<main>
  <h1>WorkSpace Security Console</h1>
  <div class="muted">ローカル専用・読み取り専用監視コンソール</div>
  <div class="grid">
    <section class="card"><div class="label">監視</div><div id="enabled" class="value">読込中</div></section>
    <section class="card"><div class="label">実ネットワーク読取</div><div id="network" class="value">読込中</div></section>
    <section class="card"><div class="label">準備状況</div><div id="ready" class="value">読込中</div></section>
    <section class="card"><div class="label">有効アセット</div><div id="assets" class="value">-</div></section>
  </div>

  <section class="card" style="margin-top:14px">
    <strong>Asset Intelligence</strong>
    <p class="muted">承認済み設定から集計値のみを表示します。アセットID、管理ホスト、資格情報参照、TCPポート値は表示しません。</p>
    <div class="grid">
      <section class="card"><div class="label">全アセット</div><div id="asset-total" class="value">-</div></section>
      <section class="card"><div class="label">無効アセット</div><div id="asset-disabled" class="value">-</div></section>
      <section class="card"><div class="label">有効ロール数</div><div id="asset-roles" class="value">-</div></section>
      <section class="card"><div class="label">資格情報参照あり</div><div id="asset-credentials" class="value">-</div></section>
      <section class="card"><div class="label">明示TCPポート割当数</div><div id="asset-port-bindings" class="value">-</div></section>
    </div>
    <pre id="asset-intelligence">Asset Intelligence を読み込んでいます...</pre>
  </section>

  <section class="card" style="margin-top:14px">
    <strong>Evidence / Result History</strong>
    <p class="muted">監視DBの直近最大100件/ストリームを集計値だけで表示します。アセットID、ソースID、Finding ID、Evidence参照、Bundle参照、RAW値は表示しません。</p>
    <div class="grid">
      <section class="card"><div class="label">監視DB</div><div id="evidence-db" class="value">-</div></section>
      <section class="card"><div class="label">監視状態</div><div id="evidence-health" class="value">-</div></section>
      <section class="card"><div class="label">Observation sample</div><div id="evidence-observations" class="value">-</div></section>
      <section class="card"><div class="label">Evidence-linked observations</div><div id="evidence-observation-links" class="value">-</div></section>
      <section class="card"><div class="label">Event sample</div><div id="evidence-events" class="value">-</div></section>
      <section class="card"><div class="label">Evidence-linked events</div><div id="evidence-event-links" class="value">-</div></section>
      <section class="card"><div class="label">Finding sample</div><div id="evidence-findings" class="value">-</div></section>
      <section class="card"><div class="label">Evidence-linked findings</div><div id="evidence-finding-links" class="value">-</div></section>
      <section class="card"><div class="label">Report sample</div><div id="evidence-reports" class="value">-</div></section>
      <section class="card"><div class="label">Open findings</div><div id="evidence-open" class="value">-</div></section>
      <section class="card"><div class="label">High / Critical</div><div id="evidence-high" class="value">-</div></section>
    </div>
    <pre id="evidence-summary">Evidence summary を読み込んでいます...</pre>
  </section>

  <section class="card" style="margin-top:14px">
    <strong>Incident Posture</strong>
    <p class="muted">直近最大100件のFindingを固定バケットの集計値だけで表示します。Finding ID、Asset参照、Evidence参照、Rule ID、Category値は表示しません。</p>
    <div class="grid">
      <section class="card"><div class="label">Attention</div><div id="incident-attention" class="value">-</div></section>
      <section class="card"><div class="label">Finding sample</div><div id="incident-sample" class="value">-</div></section>
      <section class="card"><div class="label">Open sample</div><div id="incident-open" class="value">-</div></section>
      <section class="card"><div class="label">Closed sample</div><div id="incident-closed" class="value">-</div></section>
    </div>
    <pre id="incident-posture">Incident posture を読み込んでいます...</pre>
  </section>

  <section class="card" style="margin-top:14px">
    <strong>Read-only monitoring</strong>
    <p class="muted">設定ファイルは起動時に固定されます。ブラウザから path / target / credential / shell を指定することはできません。</p>
    <button id="run" disabled>読み取り専用監視を実行</button>
    <pre id="result">準備状況を確認しています...</pre>
  </section>

  <section class="card" style="margin-top:14px">
    <strong>Readiness</strong>
    <ul id="issues"></ul>
  </section>
</main>
<script nonce="__CSP_NONCE__">
const csrf = "__CSRF_TOKEN__";
const byId = (id) => document.getElementById(id);
let summary = null;
let readiness = null;
let assetIntelligence = null;
let evidenceSummary = null;
let incidentPosture = null;

function stateText(value) { return value ? "有効" : "無効"; }
function setState(el, value) {
  el.textContent = stateText(value);
  el.className = "value " + (value ? "good" : "bad");
}

async function refresh() {
  try {
    const [summaryResp, readinessResp, assetResp, evidenceResp, incidentResp] = await Promise.all([
      fetch("/api/v1/security/monitoring/summary", {cache:"no-store"}),
      fetch("/api/v1/security/monitoring/readiness", {cache:"no-store"}),
      fetch("/api/v1/security/monitoring/asset-intelligence", {cache:"no-store"}),
      fetch("/api/v1/security/monitoring/evidence-summary", {cache:"no-store"}),
      fetch("/api/v1/security/monitoring/incident-posture", {cache:"no-store"})
    ]);
    summary = await summaryResp.json();
    readiness = await readinessResp.json();
    assetIntelligence = await assetResp.json();
    evidenceSummary = await evidenceResp.json();
    incidentPosture = await incidentResp.json();
    if (!summaryResp.ok || !readinessResp.ok || !assetResp.ok || !evidenceResp.ok || !incidentResp.ok) throw new Error("backend status unavailable");

    setState(byId("enabled"), summary.enabled === true);
    setState(byId("network"), summary.allow_real_network === true);
    byId("ready").textContent = readiness.ready ? "READY" : "BLOCKED";
    byId("ready").className = "value " + (readiness.ready ? "good" : "bad");
    byId("assets").textContent = String(summary.enabled_asset_count ?? 0);

    byId("asset-total").textContent = String(assetIntelligence.asset_count ?? 0);
    byId("asset-disabled").textContent = String(assetIntelligence.disabled_asset_count ?? 0);
    byId("asset-roles").textContent = String(assetIntelligence.unique_role_count ?? 0);
    byId("asset-credentials").textContent = String(assetIntelligence.credential_ref_asset_count ?? 0);
    byId("asset-port-bindings").textContent = String(assetIntelligence.explicit_tcp_port_binding_count ?? 0);
    byId("asset-intelligence").textContent = JSON.stringify({
      capability_counts: assetIntelligence.capability_counts || {},
      data_class_counts: assetIntelligence.data_class_counts || {},
      authority: assetIntelligence.authority || {}
    }, null, 2);

    byId("evidence-db").textContent = evidenceSummary.database_available ? "利用可能" : "利用不可";
    byId("evidence-db").className = "value " + (evidenceSummary.database_available ? "good" : "warn");
    byId("evidence-health").textContent = String(evidenceSummary.health ?? "unknown");
    byId("evidence-observations").textContent = String(evidenceSummary.observation_sample_count ?? 0);
    byId("evidence-observation-links").textContent = String(evidenceSummary.observation_evidence_linked_count ?? 0);
    byId("evidence-events").textContent = String(evidenceSummary.event_sample_count ?? 0);
    byId("evidence-event-links").textContent = String(evidenceSummary.event_evidence_linked_count ?? 0);
    byId("evidence-findings").textContent = String(evidenceSummary.finding_sample_count ?? 0);
    byId("evidence-finding-links").textContent = String(evidenceSummary.finding_evidence_linked_count ?? 0);
    byId("evidence-reports").textContent = String(evidenceSummary.report_sample_count ?? 0);
    byId("evidence-open").textContent = String(evidenceSummary.open_finding_count ?? 0);
    byId("evidence-high").textContent = String(evidenceSummary.high_critical_count ?? 0);
    byId("evidence-summary").textContent = JSON.stringify({
      count_scope: evidenceSummary.count_scope,
      max_records_per_stream: evidenceSummary.max_records_per_stream,
      reason_codes: evidenceSummary.reason_codes || [],
      latest_hourly: evidenceSummary.latest_hourly,
      authority: evidenceSummary.authority || {}
    }, null, 2);

    byId("incident-attention").textContent = String(incidentPosture.attention_level ?? "unknown");
    byId("incident-sample").textContent = String(incidentPosture.sample_count ?? 0);
    byId("incident-open").textContent = String(incidentPosture.open_sample_count ?? 0);
    byId("incident-closed").textContent = String(incidentPosture.closed_sample_count ?? 0);
    byId("incident-posture").textContent = JSON.stringify({
      count_scope: incidentPosture.count_scope,
      max_findings: incidentPosture.max_findings,
      severity_counts: incidentPosture.severity_counts || {},
      status_counts: incidentPosture.status_counts || {},
      authority: incidentPosture.authority || {}
    }, null, 2);

    const list = byId("issues");
    list.replaceChildren();
    for (const item of [...(readiness.issues || []), ...(readiness.warnings || [])]) {
      const li = document.createElement("li");
      li.textContent = `${item.code}: ${item.message}`;
      list.appendChild(li);
    }
    if (!list.children.length) {
      const li = document.createElement("li");
      li.textContent = "No readiness issues.";
      li.className = "good";
      list.appendChild(li);
    }
    byId("run").disabled = !(readiness.ready && summary.enabled && summary.allow_real_network);
    byId("result").textContent = "Backend connected. User action is required before execution.";
  } catch (error) {
    byId("result").textContent = `接続エラー: ${error.message}`;
    byId("asset-intelligence").textContent = "Asset Intelligence を取得できません。";
    byId("evidence-summary").textContent = "Evidence summary を取得できません。";
    byId("incident-posture").textContent = "Incident posture を取得できません。";
  }
}

byId("run").addEventListener("click", async () => {
  if (!window.confirm("承認済みアセットに対して読み取り専用監視を実行しますか？")) return;
  const button = byId("run");
  button.disabled = true;
  byId("result").textContent = "実行中...";
  try {
    const response = await fetch("/api/v1/security/monitoring/run-hourly", {
      method: "POST",
      headers: {"Content-Type":"application/json", "X-Workspace-CSRF": csrf},
      body: JSON.stringify({confirm_readonly:true})
    });
    const payload = await response.json();
    byId("result").textContent = JSON.stringify(payload, null, 2);
  } catch (error) {
    byId("result").textContent = `実行エラー: ${error.message}`;
  } finally {
    await refresh();
  }
});

refresh();
</script>
</body>
</html>
"""


def validate_loopback_host(host: str) -> str:
    normalized = str(host or "").strip().lower()
    if normalized not in _LOCAL_HOSTS:
        raise ValueError("SECURITY_CONSOLE_LOOPBACK_ONLY")
    return normalized


def _host_header_is_loopback(value: str | None) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    host = raw.split(":", 1)[0]
    return host in _LOCAL_HOSTS


class SecurityConsoleServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        service: SecurityMonitoringService,
        *,
        csrf_token: str | None = None,
        csp_nonce: str | None = None,
    ) -> None:
        self.service = service
        self.csrf_token = csrf_token or secrets.token_hex(32)
        self.csp_nonce = csp_nonce or secrets.token_hex(16)
        super().__init__(server_address, SecurityConsoleHandler)


class SecurityConsoleHandler(BaseHTTPRequestHandler):
    server: SecurityConsoleServer

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def _json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _html(self) -> None:
        page = _PAGE.replace("__CSRF_TOKEN__", self.server.csrf_token).replace(
            "__CSP_NONCE__", self.server.csp_nonce
        )
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; connect-src 'self'; "
            f"script-src 'nonce-{self.server.csp_nonce}'; "
            f"style-src 'nonce-{self.server.csp_nonce}'; base-uri 'none'; frame-ancestors 'none'",
        )
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _valid_host(self) -> bool:
        if _host_header_is_loopback(self.headers.get("Host")):
            return True
        self._json(421, {"status": "blocked", "reason_code": "LOOPBACK_HOST_REQUIRED"})
        return False

    def do_GET(self) -> None:  # noqa: N802
        if not self._valid_host():
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
                        "service": "workspace-security-console",
                        "local_only": True,
                        "write_authority": False,
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
        except Exception:
            self._json(500, {"status": "error", "reason_code": "CONSOLE_BACKEND_ERROR"})
            return
        self._json(404, {"status": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._valid_host():
            return
        path = urlsplit(self.path).path
        if path != "/api/v1/security/monitoring/run-hourly":
            self._json(404, {"status": "not_found"})
            return
        if not hmac.compare_digest(
            str(self.headers.get("X-Workspace-CSRF") or ""),
            self.server.csrf_token,
        ):
            self._json(403, {"status": "blocked", "reason_code": "CSRF_TOKEN_REQUIRED"})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"status": "blocked", "reason_code": "JSON_BODY_REQUIRED"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"status": "blocked", "reason_code": "INVALID_CONTENT_LENGTH"})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._json(413, {"status": "blocked", "reason_code": "REQUEST_SIZE_OUT_OF_BOUNDS"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"status": "blocked", "reason_code": "INVALID_JSON"})
            return
        if not isinstance(payload, dict) or set(payload) != {"confirm_readonly"}:
            self._json(400, {"status": "blocked", "reason_code": "UNSUPPORTED_REQUEST_FIELDS"})
            return
        if payload.get("confirm_readonly") is not True:
            self._json(409, {"status": "blocked", "reason_code": "USER_CONFIRMATION_REQUIRED"})
            return
        try:
            receipt = self.server.service.run_hourly(execute_readonly=True)
        except MonitoringRunAlreadyLocked:
            self._json(409, {"status": "blocked", "reason_code": "HOURLY_SLOT_ALREADY_LOCKED"})
            return
        except RuntimeError as exc:
            self._json(409, {"status": "blocked", "reason_code": str(exc)})
            return
        except Exception:
            self._json(500, {"status": "error", "reason_code": "CONSOLE_BACKEND_ERROR"})
            return
        self._json(200, receipt)


def build_server(
    host: str,
    port: int,
    service: SecurityMonitoringService,
    *,
    csrf_token: str | None = None,
    csp_nonce: str | None = None,
) -> SecurityConsoleServer:
    host = validate_loopback_host(host)
    if not 0 <= int(port) <= 65535:
        raise ValueError("SECURITY_CONSOLE_PORT_OUT_OF_BOUNDS")
    return SecurityConsoleServer(
        (host, int(port)),
        service,
        csrf_token=csrf_token,
        csp_nonce=csp_nonce,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workspace-security-ui")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = SecurityMonitoringService(args.config)
    server = build_server(args.host, args.port, service)
    print(
        json.dumps(
            {
                "status": "serving",
                "service": "workspace-security-console",
                "url": f"http://{args.host}:{server.server_port}/",
                "local_only": True,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

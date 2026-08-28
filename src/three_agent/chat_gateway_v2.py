from __future__ import annotations

import json
import mimetypes
import os
import queue
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import (
    SESSION_TTL_SECONDS,
    ChatApplication,
    ChatHTTPHandler,
    SessionStore,
    TelegramBridge,
    _format_handoff,
    _lan_hint,
    _parse_allowed_ids,
    _parse_request_controls,
)
from .config import load_config
from .models import TaskStatus
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text


@dataclass
class ProgressJob:
    job_id: str
    channel: str
    sender: str
    message: str
    language: str
    output_format: str
    status: str = "queued"
    task_id: str | None = None
    answer: str = ""
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    artifacts: list[str] = field(default_factory=list)
    stages: list[dict[str, str]] = field(
        default_factory=lambda: [
            {"id": "research", "label": "Agent 1 · Research", "status": "queued", "detail": ""},
            {"id": "presentation", "label": "Agent 2 · Presentation", "status": "queued", "detail": ""},
            {"id": "daily_report", "label": "Agent 3 · Daily Report", "status": "queued", "detail": ""},
        ]
    )

    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["artifacts"] = [
            {
                "name": Path(path).name,
                "url": f"/api/artifacts/{self.job_id}/{index}",
            }
            for index, path in enumerate(self.artifacts)
        ]
        return payload


def _daily_report_text(paths: list[str]) -> str:
    md = next((Path(path) for path in paths if str(path).endswith(".md")), None)
    if md is None or not md.is_file():
        return "Agent 3 did not produce a readable Markdown report."
    text = md.read_text(encoding="utf-8").strip()
    if len(text) > 16000:
        return text[:16000] + "\n\n[Daily report truncated in chat; open the artifact for the complete report.]"
    return text


class ProgressChatService:
    def __init__(self, orchestrator: Orchestrator, default_language: str = "ja") -> None:
        self.orchestrator = orchestrator
        self.default_language = default_language
        self._jobs: dict[str, ProgressJob] = {}
        self._queue: queue.Queue[str] = queue.Queue()
        self._lock = threading.RLock()
        self._worker = threading.Thread(target=self._worker_loop, name="3agent-chat-worker", daemon=True)
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._worker.start()

    def submit(self, message: str, *, channel: str, sender: str, language: str | None = None) -> ProgressJob:
        text, chosen_language, output_format = _parse_request_controls(
            message,
            language or self.default_language,
        )
        job = ProgressJob(
            job_id=uuid.uuid4().hex[:16],
            channel=channel,
            sender=redact_sensitive_text(sender)[:120],
            message=text,
            language=chosen_language,
            output_format=output_format,
        )
        with self._lock:
            self._jobs[job.job_id] = job
        self._queue.put(job.job_id)
        return ProgressJob(**asdict(job))

    def get(self, job_id: str) -> ProgressJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return ProgressJob(**asdict(job)) if job else None

    def recent(self, limit: int = 20) -> list[ProgressJob]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)[:limit]
            return [ProgressJob(**asdict(item)) for item in jobs]

    def _update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in changes.items():
                setattr(job, key, value)
            job.updated_at = time.time()

    def _stage(self, job_id: str, stage_id: str, status: str, detail: str = "") -> None:
        with self._lock:
            job = self._jobs[job_id]
            for stage in job.stages:
                if stage["id"] == stage_id:
                    stage["status"] = status
                    stage["detail"] = redact_sensitive_text(detail)[:500]
                    break
            job.updated_at = time.time()

    def _worker_loop(self) -> None:
        while True:
            job_id = self._queue.get()
            try:
                self._execute(job_id)
            finally:
                self._queue.task_done()

    def _monitor(self, job_id: str, task_id: str, stop: threading.Event) -> None:
        last_id = 0
        while not stop.wait(0.4):
            try:
                with self.orchestrator.store.connect() as conn:
                    rows = conn.execute(
                        "SELECT id,agent_id,action,status,details FROM activities WHERE task_id=? AND id>? ORDER BY id",
                        (task_id, last_id),
                    ).fetchall()
                for row in rows:
                    last_id = max(last_id, int(row["id"]))
                    action = str(row["action"])
                    status = str(row["status"])
                    detail = str(row["details"] or "")
                    if action == "research_started":
                        self._stage(job_id, "research", "running", detail)
                    elif action == "research_quality_gate":
                        self._stage(job_id, "research", "completed" if status == "ok" else "blocked", detail)
                        if status != "ok":
                            self._stage(job_id, "presentation", "skipped", "Research quality gate blocked downstream presentation.")
                            self._stage(job_id, "daily_report", "running", "Recording blocked workflow evidence.")
                    elif action == "presentation_started":
                        self._stage(job_id, "presentation", "running", detail)
                    elif action == "task_workflow_completed":
                        self._stage(job_id, "presentation", "completed", detail)
                        self._stage(job_id, "daily_report", "running", "Building evidence-bounded daily report.")
                    elif action == "workflow_stage_failed":
                        current = self.orchestrator.store.get_task(task_id)
                        if current.status == TaskStatus.FAILED:
                            if any(stage["status"] == "running" for stage in self._jobs[job_id].stages[1:2]):
                                self._stage(job_id, "presentation", "failed", detail)
                            self._stage(job_id, "daily_report", "running", "Recording failed workflow evidence.")
                    elif action == "daily_report_attached":
                        self._stage(job_id, "daily_report", "completed", detail)
            except Exception:
                continue

    def _execute(self, job_id: str) -> None:
        job = self.get(job_id)
        if job is None:
            return
        self._update(job_id, status="running")
        task = self.orchestrator.store.create_task(job.message[:96], job.message)
        self._update(job_id, task_id=task.task_id)
        self._stage(job_id, "research", "running", "Agent 1 is planning, searching and validating sources.")
        stop = threading.Event()
        monitor = threading.Thread(
            target=self._monitor,
            args=(job_id, task.task_id, stop),
            name=f"3agent-stage-{job_id}",
            daemon=True,
        )
        monitor.start()
        try:
            result = self.orchestrator.workflow.run_task(
                task.task_id,
                live=True,
                audience="R&D internal",
                purpose="answer the user request with evidence",
                language=job.language,
                slide_count=6,
                output_format=job.output_format,
            )
            handoff = next((item for item in result.research_artifacts if item.endswith("_handoff.json")), "")
            research_text, _ = _format_handoff(handoff)
            daily_text = _daily_report_text(result.daily_report_artifacts)
            answer = (
                "## Agent 1 · Research result\n\n"
                + research_text
                + "\n\n---\n\n## Agent 3 · Daily Report\n\n"
                + daily_text
            )
            artifacts = (
                list(result.research_artifacts)
                + list(result.presentation_artifacts)
                + list(result.daily_report_artifacts)
            )
            status = "completed" if result.status == "completed" else result.status
            if status == "completed":
                self._stage(job_id, "research", "completed")
                self._stage(job_id, "presentation", "completed")
                self._stage(job_id, "daily_report", "completed")
            elif status == "blocked":
                self._stage(job_id, "research", "blocked")
                self._stage(job_id, "presentation", "skipped")
                self._stage(job_id, "daily_report", "completed")
            self._update(
                job_id,
                status=status,
                answer=answer,
                error=redact_sensitive_text(result.error) if result.error else None,
                artifacts=artifacts,
            )
        except Exception as exc:
            self._stage(job_id, "daily_report", "failed")
            self._update(
                job_id,
                status="failed",
                error=redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:1200],
            )
        finally:
            stop.set()
            monitor.join(timeout=1)


HTML_V2 = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>3Agent</title>
<style>
:root{color-scheme:dark;--bg:#101113;--panel:#17191d;--line:#2a2d33;--text:#eceef2;--muted:#9aa0aa;--accent:#d7ff6e;--danger:#ff8e8e;--ok:#8be28b;--warn:#ffd36e}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;height:100vh}.shell{max-width:1040px;margin:auto;height:100vh;display:flex;flex-direction:column}.top{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}.brand{font-weight:700;font-size:18px}.dot{width:9px;height:9px;border-radius:50%;background:var(--accent)}.sub{color:var(--muted);font-size:12px;margin-left:auto}#messages{flex:1;overflow:auto;padding:28px 18px 170px}.msg{max-width:840px;margin:0 auto 20px;word-break:break-word}.who{font-size:12px;color:var(--muted);margin-bottom:5px}.bubble{padding:14px 16px;border:1px solid var(--line);border-radius:16px;background:var(--panel);white-space:pre-wrap}.user .bubble{background:#202329}.error{color:var(--danger)}.stages{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px}.stage{border:1px solid var(--line);border-radius:12px;padding:9px 10px;font-size:12px}.stage b{display:block}.stage small{color:var(--muted)}.stage.completed{border-color:#3e7048}.stage.running{border-color:#75883a}.stage.blocked,.stage.failed{border-color:#8d4c4c}.stage.skipped{opacity:.55}.artifacts{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap}.artifacts a{color:var(--accent);text-decoration:none;border:1px solid var(--line);border-radius:9px;padding:5px 8px;font-size:12px}.composer{position:fixed;left:0;right:0;bottom:0;padding:12px 18px 22px;background:linear-gradient(transparent,var(--bg) 25%)}.box{max-width:920px;margin:auto;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:10px}.row{display:flex;gap:8px;align-items:flex-end}textarea{flex:1;resize:none;min-height:52px;max-height:160px;background:transparent;border:0;outline:0;color:var(--text);padding:10px;font:inherit}button,select,input{background:#252830;color:var(--text);border:1px solid #343842;border-radius:10px;padding:9px 12px}button{cursor:pointer}button.primary{background:var(--accent);color:#151712;border-color:var(--accent);font-weight:700}.tools{display:flex;gap:8px;padding:0 8px 4px;align-items:center}.hint{color:var(--muted);font-size:11px;margin-left:auto}#login{position:fixed;inset:0;background:rgba(10,11,13,.96);z-index:5;display:flex;align-items:center;justify-content:center}.card{width:min(420px,90vw);background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px}.card input{width:100%;margin:8px 0 12px}.hidden{display:none!important}@media(max-width:700px){.stages{grid-template-columns:1fr}.sub{display:none}}
</style></head><body>
<div id="login"><div class="card"><h2>3Agent LAN</h2><p style="color:var(--muted)">Enter the server access key.</p><input id="key" type="password" placeholder="Access key"><button class="primary" onclick="login()">Connect</button><p id="loginErr" class="error"></p></div></div>
<div class="shell"><div class="top"><span class="dot"></span><span class="brand">3Agent</span><span class="sub">Agent 1 Research → Agent 2 Presentation → Agent 3 Daily Report</span></div><div id="messages"></div></div>
<div class="composer"><div class="box"><div class="tools"><select id="lang"><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select><select id="fmt"><option value="source">Chat</option><option value="pptx">PPTX</option><option value="pdf">PDF</option><option value="all">PPTX + PDF</option></select><span class="hint">LAN only · Agent 3 report appears in chat</span></div><div class="row"><textarea id="input" placeholder="Ask 3Agent..."></textarea><button class="primary" onclick="sendMsg()">Send</button></div></div></div>
<script>
const messages=document.getElementById('messages'),input=document.getElementById('input');function esc(s){return String(s||'')}function renderStages(stages){const wrap=document.createElement('div');wrap.className='stages';for(const s of stages||[]){const e=document.createElement('div');e.className='stage '+s.status;e.innerHTML='<b></b><small></small>';e.children[0].textContent=s.label+' · '+s.status;e.children[1].textContent=s.detail||'';wrap.appendChild(e)}return wrap}function renderArtifacts(items){const w=document.createElement('div');w.className='artifacts';for(const a of items||[]){const x=document.createElement('a');x.href=a.url;x.textContent='↓ '+a.name;w.appendChild(x)}return w}function add(who,text,cls='',job=null){const d=document.createElement('div');d.className='msg '+cls;const h=document.createElement('div');h.className='who';h.textContent=who;d.appendChild(h);if(job)d.appendChild(renderStages(job.stages));const b=document.createElement('div');b.className='bubble';b.textContent=text;d.appendChild(b);if(job&&job.artifacts)d.appendChild(renderArtifacts(job.artifacts));messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}function updateNode(node,j){const old=node.querySelector('.stages');if(old)old.remove();node.insertBefore(renderStages(j.stages),node.querySelector('.bubble'));const b=node.querySelector('.bubble');b.textContent=j.status==='failed'?(j.error||'Failed'):((j.status==='queued'||j.status==='running')?'Processing through 3 agents…':(j.answer||j.status));const oldA=node.querySelector('.artifacts');if(oldA)oldA.remove();if(j.artifacts&&j.artifacts.length)node.appendChild(renderArtifacts(j.artifacts));if(j.status==='failed')node.classList.add('error')}async function api(url,opt={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(opt.headers||{})},...opt});if(r.status===401){document.getElementById('login').classList.remove('hidden');throw new Error('Authentication required')}const data=await r.json();if(!r.ok)throw new Error(data.error||r.statusText);return data}async function login(){const key=document.getElementById('key').value;try{await api('/api/login',{method:'POST',body:JSON.stringify({token:key})});document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';await loadRecent()}catch(e){document.getElementById('loginErr').textContent=e.message}}async function loadRecent(){try{const d=await api('/api/recent');messages.innerHTML='';for(const j of d.jobs.reverse()){add('You',j.message,'user');add('3Agent',j.status==='failed'?(j.error||'Failed'):(j.answer||'['+j.status+']'),j.status==='failed'?'error':'',j)}}catch(e){}}async function sendMsg(){const text=input.value.trim();if(!text)return;const fmt=document.getElementById('fmt').value,lang=document.getElementById('lang').value;input.value='';add('You',text,'user');const pending=add('3Agent','Queued…','',{stages:[{label:'Agent 1 · Research',status:'queued'},{label:'Agent 2 · Presentation',status:'queued'},{label:'Agent 3 · Daily Report',status:'queued'}],artifacts:[]});try{const d=await api('/api/chat',{method:'POST',body:JSON.stringify({message:text,language:lang,format:fmt})});updateNode(pending,d);poll(d.job_id,pending)}catch(e){pending.querySelector('.bubble').textContent=e.message;pending.classList.add('error')}}async function poll(id,node){try{const j=await api('/api/jobs/'+id);updateNode(node,j);if(j.status==='queued'||j.status==='running')setTimeout(()=>poll(id,node),1200)}catch(e){node.querySelector('.bubble').textContent=e.message;node.classList.add('error')}}input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg()}});(async()=>{try{await api('/api/recent');document.getElementById('login').classList.add('hidden');await loadRecent()}catch(e){}})();
</script></body></html>'''


class ProgressHTTPHandler(ChatHTTPHandler):
    server_version = "3AgentChat/0.2"

    def do_GET(self) -> None:
        if not self._private_or_reject():
            return
        path = urlparse(self.path).path
        if path == "/":
            body = HTML_V2.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/api/artifacts/"):
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
                return
            parts = path.split("/")
            if len(parts) != 5:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                return
            job = self.app.service.get(parts[3])
            try:
                index = int(parts[4])
            except ValueError:
                index = -1
            if job is None or index < 0 or index >= len(job.artifacts):
                self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown artifact"})
                return
            candidate = Path(job.artifacts[index])
            if not candidate.is_absolute():
                candidate = Path.cwd() / candidate
            candidate = candidate.resolve()
            root = Path(self.app.artifact_root).resolve()
            if not candidate.is_relative_to(root) or not candidate.is_file():
                self._json(HTTPStatus.FORBIDDEN, {"error": "Artifact path rejected"})
                return
            body = candidate.read_bytes()
            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{candidate.name}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


class ProgressApplication(ChatApplication):
    def __init__(self, service: ProgressChatService, sessions: SessionStore, artifact_root: Path) -> None:
        super().__init__(service, sessions)
        self.artifact_root = artifact_root


def main() -> int:
    config = load_config()
    orchestrator = Orchestrator(config)
    orchestrator.initialize()
    access_token = os.getenv("THREE_AGENT_WEB_ACCESS_TOKEN", "")
    host = os.getenv("THREE_AGENT_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("THREE_AGENT_WEB_PORT", "8787"))
    language = os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja")
    service = ProgressChatService(orchestrator, default_language=language)
    service.start()
    sessions = SessionStore(access_token)
    app = ProgressApplication(service, sessions, config.artifact_root)
    telegram_token = os.getenv("THREE_AGENT_TELEGRAM_BOT_TOKEN", "").strip()
    allowed_ids = _parse_allowed_ids(os.getenv("THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS", ""))
    if telegram_token:
        bridge = TelegramBridge(service, orchestrator.internet_gateway, telegram_token, allowed_ids)
        threading.Thread(target=bridge.run_forever, name="3agent-telegram", daemon=True).start()
        print(f"[3Agent-Chat] Telegram enabled; authorized users={len(allowed_ids)}.", flush=True)
    else:
        print("[3Agent-Chat] Telegram disabled (no bot token configured).", flush=True)
    httpd = ThreadingHTTPServer((host, port), ProgressHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[3Agent-Chat] LAN UI: {_lan_hint(host, port)}", flush=True)
    print("[3Agent-Chat] Three-agent live progress and Agent 3 report-in-chat enabled.", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

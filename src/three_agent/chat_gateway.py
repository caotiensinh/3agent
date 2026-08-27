from __future__ import annotations

import hmac
import ipaddress
import json
import mimetypes
import os
import queue
import secrets
import socket
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text

MAX_MESSAGE_CHARS = 12000
SESSION_TTL_SECONDS = 12 * 60 * 60


@dataclass
class ChatJob:
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

    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["message"] = self.message
        return payload


def _private_client(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _parse_request_controls(message: str, default_language: str = "ja") -> tuple[str, str, str]:
    text = " ".join(str(message or "").split())
    language = default_language if default_language in {"ja", "en", "vi"} else "ja"
    output_format = "source"

    changed = True
    while changed:
        changed = False
        lower = text.lower()
        for prefix, value in (("/ja ", "ja"), ("/en ", "en"), ("/vi ", "vi")):
            if lower.startswith(prefix):
                language = value
                text = text[len(prefix) :].strip()
                changed = True
                break
        if changed:
            continue
        for prefix, value in (
            ("/pptx ", "pptx"),
            ("/pdf ", "pdf"),
            ("/all ", "all"),
            ("/source ", "source"),
        ):
            if lower.startswith(prefix):
                output_format = value
                text = text[len(prefix) :].strip()
                changed = True
                break

    if not text:
        raise ValueError("Message is empty after command prefixes")
    if len(text) > MAX_MESSAGE_CHARS:
        raise ValueError(f"Message exceeds {MAX_MESSAGE_CHARS} characters")
    return text, language, output_format


def _format_handoff(path: str | Path) -> tuple[str, list[str]]:
    handoff_path = Path(path)
    if not handoff_path.is_file():
        return "No research handoff was produced.", []
    payload = json.loads(handoff_path.read_text(encoding="utf-8"))
    lines: list[str] = []
    conclusion = str(payload.get("conclusion") or "").strip()
    if conclusion:
        lines.append(conclusion)
    blockers = [str(item) for item in payload.get("blockers") or []]
    if blockers:
        lines.append("Blocked: " + ", ".join(blockers))
    facts = payload.get("key_facts") or []
    if facts:
        lines.append("")
        lines.append("Key facts:")
        for item in facts[:8]:
            refs = ", ".join(item.get("source_ids") or [])
            suffix = f" [{refs}]" if refs else ""
            lines.append(f"- {item.get('claim', '')}{suffix}")
    unresolved = payload.get("unresolved_items") or []
    if unresolved:
        lines.append("")
        lines.append("Unresolved:")
        for item in unresolved[:5]:
            lines.append(f"- {item}")
    sources = payload.get("sources") or []
    if sources:
        lines.append("")
        lines.append("Sources:")
        for item in sources[:6]:
            lines.append(f"- [{item.get('source_id')}] {item.get('title')}: {item.get('url')}")
    return "\n".join(lines).strip() or "Workflow completed without a textual summary.", blockers


class ChatService:
    def __init__(self, orchestrator: Orchestrator, default_language: str = "ja") -> None:
        self.orchestrator = orchestrator
        self.default_language = default_language
        self._jobs: dict[str, ChatJob] = {}
        self._queue: queue.Queue[str] = queue.Queue()
        self._lock = threading.RLock()
        self._worker = threading.Thread(target=self._worker_loop, name="3agent-chat-worker", daemon=True)
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._worker.start()

    def submit(self, message: str, *, channel: str, sender: str, language: str | None = None) -> ChatJob:
        text, chosen_language, output_format = _parse_request_controls(
            message,
            language or self.default_language,
        )
        job = ChatJob(
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
        return ChatJob(**asdict(job))

    def get(self, job_id: str) -> ChatJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return ChatJob(**asdict(job)) if job else None

    def recent(self, limit: int = 20) -> list[ChatJob]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)[:limit]
            return [ChatJob(**asdict(item)) for item in jobs]

    def _update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in changes.items():
                setattr(job, key, value)
            job.updated_at = time.time()

    def _worker_loop(self) -> None:
        while True:
            job_id = self._queue.get()
            try:
                self._execute(job_id)
            finally:
                self._queue.task_done()

    def _execute(self, job_id: str) -> None:
        job = self.get(job_id)
        if job is None:
            return
        self._update(job_id, status="running")
        try:
            result = self.orchestrator.run_workflow(
                title=job.message[:96],
                request=job.message,
                live=True,
                audience="R&D internal",
                purpose="answer the user request with evidence",
                language=job.language,
                slide_count=6,
                output_format=job.output_format,
            )
            handoff = next((item for item in result.research_artifacts if item.endswith("_handoff.json")), "")
            answer, _ = _format_handoff(handoff)
            artifacts = list(result.presentation_artifacts) + list(result.daily_report_artifacts)
            status = "completed" if result.status == "completed" else result.status
            self._update(
                job_id,
                status=status,
                task_id=result.task_id,
                answer=answer,
                error=redact_sensitive_text(result.error) if result.error else None,
                artifacts=artifacts,
            )
        except Exception as exc:
            self._update(
                job_id,
                status="failed",
                error=redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:1200],
            )


class SessionStore:
    def __init__(self, access_token: str) -> None:
        if len(access_token) < 16:
            raise ValueError("THREE_AGENT_WEB_ACCESS_TOKEN must contain at least 16 characters")
        self.access_token = access_token
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def login(self, supplied: str, client_ip: str) -> str | None:
        if not hmac.compare_digest(self.access_token, supplied):
            return None
        session = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[session] = (client_ip, time.time() + SESSION_TTL_SECONDS)
        return session

    def valid(self, session: str, client_ip: str) -> bool:
        if not session:
            return False
        with self._lock:
            record = self._sessions.get(session)
            if record is None:
                return False
            bound_ip, expires = record
            if expires < time.time() or bound_ip != client_ip:
                self._sessions.pop(session, None)
                return False
            return True

    def logout(self, session: str) -> None:
        with self._lock:
            self._sessions.pop(session, None)


class TelegramBridge:
    def __init__(
        self,
        service: ChatService,
        internet_gateway: Any,
        bot_token: str,
        allowed_user_ids: set[int],
    ) -> None:
        self.service = service
        self.gateway = internet_gateway
        self.bot_token = bot_token
        self.allowed_user_ids = allowed_user_ids
        self.offset = 0

    def _url(self, method: str) -> str:
        return f"https://api.telegram.org/bot{self.bot_token}/{method}"

    def _api(self, method: str, payload: dict[str, Any], timeout: int = 40) -> dict[str, Any]:
        raw = self.gateway.post_json("telegram", None, self._url(method), payload, timeout=timeout)
        data = json.loads(raw.decode("utf-8"))
        if not data.get("ok"):
            raise RuntimeError(f"Telegram API {method} failed")
        return data

    def send(self, chat_id: int, text: str) -> None:
        safe = str(text or "")
        chunks = [safe[index : index + 3900] for index in range(0, len(safe), 3900)] or ["(empty)"]
        for chunk in chunks:
            self._api("sendMessage", {"chat_id": chat_id, "text": chunk}, timeout=20)

    def _notify_when_done(self, chat_id: int, job_id: str) -> None:
        while True:
            job = self.service.get(job_id)
            if job is None:
                return
            if job.status not in {"queued", "running"}:
                if job.status == "completed":
                    self.send(chat_id, f"{job.answer}\n\nTask: {job.task_id or '-'}")
                elif job.status == "blocked":
                    self.send(chat_id, f"Research gate blocked this request.\n\n{job.answer}\n\nTask: {job.task_id or '-'}")
                else:
                    self.send(chat_id, f"3Agent failed: {job.error or job.status}\nTask: {job.task_id or '-'}")
                return
            time.sleep(2)

    def handle_update(self, update: dict[str, Any]) -> None:
        message = update.get("message")
        if not isinstance(message, dict):
            return
        text = message.get("text")
        sender = message.get("from") or {}
        chat = message.get("chat") or {}
        if not isinstance(text, str) or not text.strip():
            return
        user_id = int(sender.get("id") or 0)
        chat_id = int(chat.get("id") or 0)
        if not user_id or not chat_id:
            return
        if text.strip().lower() in {"/id", "/whoami"}:
            self.send(chat_id, f"Telegram user ID: {user_id}")
            return
        if user_id not in self.allowed_user_ids:
            self.send(chat_id, f"Not authorized. Your Telegram user ID is {user_id}.")
            return
        if text.strip().lower() == "/help":
            self.send(
                chat_id,
                "Send a request normally. Prefix with /ja, /vi or /en for language; /pptx, /pdf, /all or /source for output. Example: /vi /pptx Nghiên cứu AI camera giao thông.",
            )
            return
        job = self.service.submit(text, channel="telegram", sender=str(user_id))
        self.send(chat_id, f"Accepted: {job.job_id}. 3Agent is processing it.")
        threading.Thread(
            target=self._notify_when_done,
            args=(chat_id, job.job_id),
            name=f"telegram-notify-{job.job_id}",
            daemon=True,
        ).start()

    def run_forever(self) -> None:
        try:
            self._api("deleteWebhook", {"drop_pending_updates": False}, timeout=20)
        except Exception:
            pass
        while True:
            try:
                data = self._api(
                    "getUpdates",
                    {
                        "offset": self.offset,
                        "timeout": 25,
                        "allowed_updates": ["message"],
                    },
                    timeout=35,
                )
                for update in data.get("result") or []:
                    self.offset = max(self.offset, int(update.get("update_id") or 0) + 1)
                    self.handle_update(update)
            except Exception as exc:
                print(f"[3Agent-Chat][Telegram] {redact_sensitive_text(str(exc))}", flush=True)
                time.sleep(5)


HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>3Agent</title>
<style>
:root{color-scheme:dark;--bg:#101113;--panel:#17191d;--line:#2a2d33;--text:#eceef2;--muted:#9aa0aa;--accent:#d7ff6e;--danger:#ff8e8e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;height:100vh}
.shell{max-width:980px;margin:auto;height:100vh;display:flex;flex-direction:column}.top{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}.brand{font-weight:700;font-size:18px}.dot{width:9px;height:9px;border-radius:50%;background:var(--accent)}.sub{color:var(--muted);font-size:12px;margin-left:auto}
#messages{flex:1;overflow:auto;padding:28px 18px 150px}.msg{max-width:780px;margin:0 auto 18px;white-space:pre-wrap;word-break:break-word}.who{font-size:12px;color:var(--muted);margin-bottom:5px}.bubble{padding:14px 16px;border:1px solid var(--line);border-radius:16px;background:var(--panel)}.user .bubble{background:#202329}.error{color:var(--danger)}
.composer{position:fixed;left:0;right:0;bottom:0;padding:12px 18px 22px;background:linear-gradient(transparent,var(--bg) 25%)}.box{max-width:900px;margin:auto;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:10px}.row{display:flex;gap:8px;align-items:flex-end}textarea{flex:1;resize:none;min-height:52px;max-height:160px;background:transparent;border:0;outline:0;color:var(--text);padding:10px;font:inherit}button,select,input{background:#252830;color:var(--text);border:1px solid #343842;border-radius:10px;padding:9px 12px}button{cursor:pointer}button.primary{background:var(--accent);color:#151712;border-color:var(--accent);font-weight:700}.tools{display:flex;gap:8px;padding:0 8px 4px;align-items:center}.hint{color:var(--muted);font-size:11px;margin-left:auto}
#login{position:fixed;inset:0;background:rgba(10,11,13,.96);z-index:5;display:flex;align-items:center;justify-content:center}.card{width:min(420px,90vw);background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px}.card h2{margin-top:0}.card input{width:100%;margin:8px 0 12px}.hidden{display:none!important}a{color:var(--accent)}
</style>
</head>
<body>
<div id="login"><div class="card"><h2>3Agent LAN</h2><p style="color:var(--muted)">Enter the access key printed by the server setup.</p><input id="key" type="password" autocomplete="current-password" placeholder="Access key"><button class="primary" onclick="login()">Connect</button><p id="loginErr" class="error"></p></div></div>
<div class="shell"><div class="top"><span class="dot"></span><span class="brand">3Agent</span><span class="sub">Research → Presentation → Daily Report</span></div><div id="messages"></div></div>
<div class="composer"><div class="box"><div class="tools"><select id="lang"><option value="ja">日本語</option><option value="vi">Tiếng Việt</option><option value="en">English</option></select><select id="fmt"><option value="source">Chat</option><option value="pptx">PPTX</option><option value="pdf">PDF</option><option value="all">PPTX + PDF</option></select><span class="hint">LAN only</span></div><div class="row"><textarea id="input" placeholder="Ask 3Agent..."></textarea><button class="primary" onclick="sendMsg()">Send</button></div></div></div>
<script>
const messages=document.getElementById('messages'), input=document.getElementById('input');
function add(who,text,cls=''){const d=document.createElement('div');d.className='msg '+cls;d.innerHTML='<div class="who"></div><div class="bubble"></div>';d.children[0].textContent=who;d.children[1].textContent=text;messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}
async function api(url,opt={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(opt.headers||{})},...opt});if(r.status===401){document.getElementById('login').classList.remove('hidden');throw new Error('Authentication required')}const data=await r.json();if(!r.ok)throw new Error(data.error||r.statusText);return data}
async function login(){const key=document.getElementById('key').value;try{await api('/api/login',{method:'POST',body:JSON.stringify({token:key})});document.getElementById('login').classList.add('hidden');document.getElementById('loginErr').textContent='';await loadRecent()}catch(e){document.getElementById('loginErr').textContent=e.message}}
async function loadRecent(){try{const d=await api('/api/recent');messages.innerHTML='';for(const j of d.jobs.reverse()){add('You',j.message,'user');const text=j.status==='completed'||j.status==='blocked'?j.answer:(j.status==='failed'?(j.error||'Failed'):'['+j.status+']');add('3Agent',text,j.status==='failed'?'error':'')}}catch(e){}}
async function sendMsg(){const text=input.value.trim();if(!text)return;const fmt=document.getElementById('fmt').value,lang=document.getElementById('lang').value;input.value='';add('You',text,'user');const pending=add('3Agent','Queued…');try{const d=await api('/api/chat',{method:'POST',body:JSON.stringify({message:text,language:lang,format:fmt})});poll(d.job_id,pending)}catch(e){pending.children[1].textContent=e.message;pending.classList.add('error')}}
async function poll(id,node){try{const j=await api('/api/jobs/'+id);if(j.status==='queued'||j.status==='running'){node.children[1].textContent=j.status==='queued'?'Queued…':'Working through 3 agents…';setTimeout(()=>poll(id,node),2000);return}node.children[1].textContent=j.status==='failed'?(j.error||'Failed'):(j.answer||j.status);if(j.status==='failed')node.classList.add('error')}catch(e){node.children[1].textContent=e.message;node.classList.add('error')}}
input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg()}});
(async()=>{try{await api('/api/recent');document.getElementById('login').classList.add('hidden');await loadRecent()}catch(e){}})();
</script></body></html>'''


class ChatHTTPHandler(BaseHTTPRequestHandler):
    server_version = "3AgentChat/0.1"

    @property
    def app(self) -> Any:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[3Agent-Chat][HTTP] {self.client_address[0]} {fmt % args}", flush=True)

    def _json(self, status: int, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > 128 * 1024:
            raise ValueError("Invalid request body size")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def _session_id(self) -> str:
        cookie = SimpleCookie(self.headers.get("Cookie") or "")
        morsel = cookie.get("three_agent_session")
        return morsel.value if morsel else ""

    def _authorized(self) -> bool:
        return self.app.sessions.valid(self._session_id(), self.client_address[0])

    def _private_or_reject(self) -> bool:
        if _private_client(self.client_address[0]):
            return True
        self._json(HTTPStatus.FORBIDDEN, {"error": "LAN/private clients only"})
        return False

    def do_GET(self) -> None:
        if not self._private_or_reject():
            return
        path = urlparse(self.path).path
        if path == "/":
            body = HTML.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/health":
            self._json(HTTPStatus.OK, {"status": "ok", "service": "3Agent Chat"})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            return
        if path == "/api/recent":
            self._json(HTTPStatus.OK, {"jobs": [job.public_dict() for job in self.app.service.recent()]})
            return
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            job = self.app.service.get(job_id)
            if job is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown job"})
            else:
                self._json(HTTPStatus.OK, job.public_dict())
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self._private_or_reject():
            return
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except Exception as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        if path == "/api/login":
            session = self.app.sessions.login(str(payload.get("token") or ""), self.client_address[0])
            if session is None:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid access key"})
                return
            cookie = f"three_agent_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL_SECONDS}"
            self._json(HTTPStatus.OK, {"status": "ok"}, {"Set-Cookie": cookie})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            return
        if path == "/api/logout":
            self.app.sessions.logout(self._session_id())
            self._json(
                HTTPStatus.OK,
                {"status": "ok"},
                {"Set-Cookie": "three_agent_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
            )
            return
        if path == "/api/chat":
            try:
                message = str(payload.get("message") or "")
                language = str(payload.get("language") or self.app.service.default_language)
                fmt = str(payload.get("format") or "source")
                prefix = "" if fmt == "source" else f"/{fmt} "
                job = self.app.service.submit(
                    prefix + message,
                    channel="web",
                    sender=self.client_address[0],
                    language=language,
                )
                self._json(HTTPStatus.ACCEPTED, job.public_dict())
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})


class ChatApplication:
    def __init__(self, service: ChatService, sessions: SessionStore) -> None:
        self.service = service
        self.sessions = sessions


def _parse_allowed_ids(raw: str) -> set[int]:
    values: set[int] = set()
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if item:
            values.add(int(item))
    return values


def _lan_hint(host: str, port: int) -> str:
    if host not in {"0.0.0.0", "::"}:
        return f"http://{host}:{port}/"
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("1.1.1.1", 80))
        ip = probe.getsockname()[0]
        probe.close()
        return f"http://{ip}:{port}/"
    except Exception:
        return f"http://<LAN-IP>:{port}/"


def main() -> int:
    config = load_config()
    orchestrator = Orchestrator(config)
    orchestrator.initialize()

    access_token = os.getenv("THREE_AGENT_WEB_ACCESS_TOKEN", "")
    host = os.getenv("THREE_AGENT_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("THREE_AGENT_WEB_PORT", "8787"))
    language = os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja")

    service = ChatService(orchestrator, default_language=language)
    service.start()
    sessions = SessionStore(access_token)
    app = ChatApplication(service, sessions)

    telegram_token = os.getenv("THREE_AGENT_TELEGRAM_BOT_TOKEN", "").strip()
    allowed_ids = _parse_allowed_ids(os.getenv("THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS", ""))
    if telegram_token:
        bridge = TelegramBridge(service, orchestrator.internet_gateway, telegram_token, allowed_ids)
        threading.Thread(target=bridge.run_forever, name="3agent-telegram", daemon=True).start()
        print(
            f"[3Agent-Chat] Telegram enabled; authorized users={len(allowed_ids)}. /id is available before authorization.",
            flush=True,
        )
    else:
        print("[3Agent-Chat] Telegram disabled (no bot token configured).", flush=True)

    httpd = ThreadingHTTPServer((host, port), ChatHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[3Agent-Chat] LAN UI: {_lan_hint(host, port)}", flush=True)
    print("[3Agent-Chat] Non-private client addresses are rejected.", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

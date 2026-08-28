from __future__ import annotations

import base64
import json
import os
import threading
import uuid
from dataclasses import asdict
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import (
    SessionStore,
    TelegramBridge,
    _lan_hint,
    _parse_allowed_ids,
    _parse_request_controls,
)
from .chat_gateway_v2 import ProgressApplication, ProgressJob
from .chat_gateway_v3 import HTML_V3, HumanReportChatService, HumanReportHTTPHandler
from .config import load_config
from .human_report import create_human_report
from .knowledge_gateway import MAX_UPLOAD_BYTES, MAX_UPLOADS_PER_TASK, UploadSecurityError
from .models import TaskStatus
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text

MAX_UPLOAD_REQUEST_BYTES = 24 * 1024 * 1024


class KnowledgeChatService(HumanReportChatService):
    def __init__(self, orchestrator: Orchestrator, default_language: str = "ja") -> None:
        super().__init__(orchestrator, default_language=default_language)
        self._job_uploads: dict[str, list[str]] = {}

    def submit(
        self,
        message: str,
        *,
        channel: str,
        sender: str,
        language: str | None = None,
        upload_ids: list[str] | None = None,
    ) -> ProgressJob:
        text, chosen_language, output_format = _parse_request_controls(
            message,
            language or self.default_language,
        )
        validated_uploads = self.orchestrator.knowledge_gateway.validate_upload_ids(upload_ids or [])
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
            self._job_uploads[job.job_id] = validated_uploads
        self._queue.put(job.job_id)
        return ProgressJob(**asdict(job))

    def _execute(self, job_id: str) -> None:
        job = self.get(job_id)
        if job is None:
            return
        self._update(job_id, status="running")
        task = self.orchestrator.store.create_task(job.message[:96], job.message)
        uploads = list(self._job_uploads.get(job_id, []))
        if uploads:
            self.orchestrator.store.attach_uploads(task.task_id, uploads)
            self.orchestrator.store.record_activity(
                task.task_id,
                "knowledge_gateway",
                "uploads_attached",
                "ok",
                f"count={len(uploads)}",
            )
        self._update(job_id, task_id=task.task_id)
        self._stage(
            job_id,
            "research",
            "running",
            "Agent 1 is validating uploaded evidence and searching public web sources.",
        )
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
            handoff = next(
                (item for item in result.research_artifacts if item.endswith("_handoff.json")),
                "",
            )

            report_paths: list[str] = []
            answer = ""
            report_warnings: list[str] = []
            if handoff:
                bundle = create_human_report(
                    task_id=task.task_id,
                    title=task.title,
                    request=task.request,
                    handoff_path=handoff,
                    artifact_root=self.orchestrator.artifacts.root,
                    language=job.language,
                )
                answer = bundle.markdown
                report_paths = list(bundle.paths)
                report_warnings = list(bundle.warnings)
                for path in report_paths:
                    suffix = Path(path).suffix.lower().lstrip(".") or "file"
                    self.orchestrator.store.record_artifact(
                        task.task_id,
                        "daily_report",
                        f"human_report_{suffix}",
                        path,
                    )
                self.orchestrator.store.record_activity(
                    task.task_id,
                    "daily_report",
                    "human_report_created",
                    "ok" if not report_warnings else "warning",
                    "outputs=" + ",".join(Path(x).suffix.lstrip(".") for x in report_paths),
                )
            else:
                answer = (
                    "# 3Agent Report\n\n"
                    "The workflow did not produce a validated research handoff, so a reader-facing "
                    "report could not be generated without inventing content.\n"
                )

            if report_warnings:
                answer += "\n\n> " + " | ".join(report_warnings)

            artifacts = list(
                dict.fromkeys(
                    report_paths
                    + list(result.presentation_artifacts)
                    + list(result.research_artifacts)
                    + list(result.daily_report_artifacts)
                )
            )
            status = "completed" if result.status == "completed" else result.status
            if status == "completed":
                self._stage(job_id, "research", "completed")
                self._stage(job_id, "presentation", "completed")
                self._stage(job_id, "daily_report", "completed", "Reader report and audit log are ready.")
            elif status == "blocked":
                self._stage(job_id, "research", "blocked")
                self._stage(job_id, "presentation", "skipped")
                self._stage(job_id, "daily_report", "completed", "Blocker report recorded.")
            elif status == "failed":
                current = self.orchestrator.store.get_task(task.task_id)
                if current.status == TaskStatus.FAILED:
                    running_presentation = any(
                        stage["id"] == "presentation" and stage["status"] == "running"
                        for stage in self._jobs[job_id].stages
                    )
                    if running_presentation:
                        self._stage(job_id, "presentation", "failed")
                self._stage(job_id, "daily_report", "completed", "Failure evidence recorded.")

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


_UPLOAD_CONTROLS = r'''
<button type="button" id="attachBtn" onclick="document.getElementById('fileInput').click()">＋ Attach</button>
<input id="fileInput" type="file" multiple hidden accept=".txt,.md,.markdown,.html,.htm,.zip,.png,.jpg,.jpeg,.webp,text/plain,text/markdown,text/html,application/zip,image/png,image/jpeg,image/webp">
'''

_UPLOAD_LIST = r'''<div id="uploadList" style="display:none;padding:5px 9px 8px;color:var(--muted);font-size:12px"></div>'''

_UPLOAD_SCRIPT = r'''
<script>
let selectedFiles=[];
const fileInputEl=document.getElementById('fileInput'),uploadListEl=document.getElementById('uploadList');
function renderUploadList(){if(!selectedFiles.length){uploadListEl.style.display='none';uploadListEl.textContent='';return}uploadListEl.style.display='block';uploadListEl.textContent='Attached: '+selectedFiles.map(f=>f.name+' ('+Math.ceil(f.size/1024)+' KB)').join(' · ')}
fileInputEl.addEventListener('change',()=>{selectedFiles=Array.from(fileInputEl.files||[]).slice(0,8);renderUploadList()});
function fileBase64(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>{const value=String(reader.result||'');resolve(value.includes(',')?value.split(',',2)[1]:value)};reader.onerror=()=>reject(reader.error||new Error('File read failed'));reader.readAsDataURL(file)})}
async function uploadOne(file){if(file.size>16*1024*1024)throw new Error(file.name+': maximum upload size is 16 MiB');const data=await fileBase64(file);return api('/api/upload',{method:'POST',body:JSON.stringify({name:file.name,type:file.type||'',data_base64:data})})}
sendMsg=async function(){const text=input.value.trim();if(!text)return;const fmt=document.getElementById('fmt').value,lang=document.getElementById('lang').value;const files=selectedFiles.slice();const names=files.map(f=>f.name);input.value='';selectedFiles=[];fileInputEl.value='';renderUploadList();add('You',text+(names.length?'\n\nAttached: '+names.join(', '):''),'user');const pending=add('3Agent',files.length?'Uploading and validating files…':'Queued…','',{answer:'',stages:[{label:'Agent 1 · Research',status:'queued'},{label:'Agent 2 · Presentation',status:'queued'},{label:'Agent 3 · Human Report',status:'queued'}],artifacts:[]});try{const uploadIds=[];for(let i=0;i<files.length;i++){pending.querySelector('.bubble').textContent='Uploading '+(i+1)+'/'+files.length+': '+files[i].name;const result=await uploadOne(files[i]);uploadIds.push(result.upload_id)}const d=await api('/api/chat',{method:'POST',body:JSON.stringify({message:text,language:lang,format:fmt,upload_ids:uploadIds})});updateNode(pending,d);poll(d.job_id,pending)}catch(e){pending.querySelector('.bubble').textContent=e.message;pending.classList.add('error')}};
</script>
'''

HTML_V4 = HTML_V3.replace(
    '<span class="hint">Every completed task includes DOCX/PDF reader report</span>',
    _UPLOAD_CONTROLS + '<span class="hint">Web search + secure uploads · DOCX/PDF report</span>',
    1,
).replace(
    '<div class="row"><textarea id="input"',
    _UPLOAD_LIST + '<div class="row"><textarea id="input"',
    1,
).replace(
    '</body></html>',
    _UPLOAD_SCRIPT + '</body></html>',
    1,
)


class KnowledgeHTTPHandler(HumanReportHTTPHandler):
    server_version = "3AgentChat/0.4"

    def _read_json_large(self, maximum: int) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > maximum:
            raise ValueError("Invalid request body size")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V4.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in {"/api/upload", "/api/chat"}:
            super().do_POST()
            return
        if not self._private_or_reject():
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            return

        try:
            payload = self._read_json_large(
                MAX_UPLOAD_REQUEST_BYTES if path == "/api/upload" else 128 * 1024
            )
            if path == "/api/upload":
                encoded = str(payload.get("data_base64") or "")
                if not encoded:
                    raise UploadSecurityError("Upload body is empty")
                try:
                    data = base64.b64decode(encoded, validate=True)
                except Exception as exc:
                    raise UploadSecurityError("Upload is not valid base64") from exc
                if len(data) > MAX_UPLOAD_BYTES:
                    raise UploadSecurityError("Upload exceeds 16 MiB per-file limit")
                record = self.app.service.orchestrator.knowledge_gateway.ingest_upload(
                    str(payload.get("name") or ""),
                    data,
                    content_type=str(payload.get("type") or ""),
                    sender=self.client_address[0],
                )
                response = record.public_dict()
                response["status"] = "accepted"
                self._json(HTTPStatus.CREATED, response)
                return

            message = str(payload.get("message") or "")
            language = str(payload.get("language") or self.app.service.default_language)
            fmt = str(payload.get("format") or "source")
            raw_uploads = payload.get("upload_ids") or []
            if not isinstance(raw_uploads, list):
                raise UploadSecurityError("upload_ids must be an array")
            if len(raw_uploads) > MAX_UPLOADS_PER_TASK:
                raise UploadSecurityError(f"At most {MAX_UPLOADS_PER_TASK} uploads may be attached to one task")
            upload_ids = self.app.service.orchestrator.knowledge_gateway.validate_upload_ids(
                [str(item) for item in raw_uploads]
            )
            prefix = "" if fmt == "source" else f"/{fmt} "
            job = self.app.service.submit(
                prefix + message,
                channel="web",
                sender=self.client_address[0],
                language=language,
                upload_ids=upload_ids,
            )
            self._json(HTTPStatus.ACCEPTED, job.public_dict())
        except (ValueError, UploadSecurityError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": redact_sensitive_text(str(exc))[:800]})


def main() -> int:
    config = load_config()
    orchestrator = Orchestrator(config)
    orchestrator.initialize()
    access_token = os.getenv("THREE_AGENT_WEB_ACCESS_TOKEN", "")
    host = os.getenv("THREE_AGENT_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("THREE_AGENT_WEB_PORT", "8787"))
    language = os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja")
    service = KnowledgeChatService(orchestrator, default_language=language)
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
    httpd = ThreadingHTTPServer((host, port), KnowledgeHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[3Agent-Chat] LAN UI: {_lan_hint(host, port)}", flush=True)
    print("[3Agent-Chat] KnowledgeGateway enabled: public-web search + secure txt/md/html/zip/image uploads.", flush=True)
    print("[3Agent-Chat] Uploaded images are stored/validated but not semantically interpreted without a local vision model.", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

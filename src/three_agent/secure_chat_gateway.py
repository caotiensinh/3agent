from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any
from urllib.parse import urlparse

from . import chat_gateway as legacy
from . import web_research
from .internet_egress_consent import (
    CONSENT_POLICY_VERSION,
    InternetEgressBlocked,
    InternetEgressConsentGuard,
    InternetEgressConsentRequired,
    strict_public_search_query,
)

_SECURE_CONSENT_UI_VERSION = "workspace.internet-egress-consent-ui/v1"
_BASE_CAPABILITIES = legacy.workspace_ui_capabilities


def _requires_public_egress(mode: str, output_format: str) -> bool:
    """Match the current WorkSpace routing contract exactly.

    Direct source chat stays local. Explicit web/deep research and artifact-producing
    requests use the research workflow and therefore must pass the Internet egress
    consent boundary before any public search can start.
    """

    return str(mode) in {"web_search", "deep_research"} or str(output_format) != "source"


def _format_research_message(output_format: str, safe_query: str) -> str:
    prefix = "" if output_format == "source" else f"/{output_format} "
    return prefix + safe_query


class SecureContinuitySecurityAwareProjectChatService(
    legacy.ContinuitySecurityAwareProjectChatService
):
    """Current WorkSpace chat plus mandatory declassification consent.

    Raw prompts, conversation history and uploads remain in the local WorkSpace
    trust domain. A public research task receives only the consent-authorized,
    sanitized query. Raw upload text is never used as the outbound query.
    """

    def __init__(self, orchestrator: Any, default_language: str = "ja") -> None:
        super().__init__(orchestrator, default_language=default_language)
        self.internet_egress_consent = InternetEgressConsentGuard()

    def submit(
        self,
        message: str,
        *,
        channel: str,
        sender: str,
        language: str | None = None,
        upload_ids: list[str] | None = None,
        request_mode: str = "chat",
        effort: str = "high",
        conversation_id: str | None = None,
        egress_consent_token: str = "",
    ) -> Any:
        controls = legacy.parse_chat_request(
            message,
            selected_language=language if language is not None else "auto",
            fallback_language=self.default_language,
        )
        mode, effort_level = legacy._validate_request_options(  # noqa: SLF001
            request_mode,
            effort,
            self.orchestrator.config,
        )

        if not _requires_public_egress(mode, controls.output_format):
            return super().submit(
                message,
                channel=channel,
                sender=sender,
                language=language,
                upload_ids=upload_ids,
                request_mode=mode,
                effort=effort_level,
                conversation_id=conversation_id,
            )

        try:
            safe_query = self.internet_egress_consent.authorize(
                controls.text,
                sender=sender,
                mode=mode,
                output_format=controls.output_format,
                consent_token=egress_consent_token,
            )
        except InternetEgressConsentRequired as exc:
            self.orchestrator.store.record_activity(
                None,
                "internet_egress_consent",
                "egress_consent_required",
                "blocked",
                " ".join(
                    [
                        f"policy={CONSENT_POLICY_VERSION}",
                        f"sensitivity={exc.preflight.sensitivity}",
                        f"removed={exc.preflight.removed_sensitive_fields}",
                        "raw_sent=false",
                        "uploads_sent=false",
                    ]
                ),
            )
            raise
        except InternetEgressBlocked as exc:
            self.orchestrator.store.record_activity(
                None,
                "internet_egress_consent",
                "egress_blocked",
                "blocked",
                " ".join(
                    [
                        f"policy={CONSENT_POLICY_VERSION}",
                        f"sensitivity={exc.preflight.sensitivity}",
                        "raw_sent=false",
                        "uploads_sent=false",
                    ]
                ),
            )
            raise

        preflight = self.internet_egress_consent.preflight(controls.text)
        self.orchestrator.store.record_activity(
            None,
            "internet_egress_consent",
            "egress_query_authorized",
            "ok",
            " ".join(
                [
                    f"policy={CONSENT_POLICY_VERSION}",
                    f"sensitivity={preflight.sensitivity}",
                    f"consent={'true' if preflight.warning_required else 'not_required'}",
                    f"removed={preflight.removed_sensitive_fields}",
                    f"uploads_local_only={len(upload_ids or [])}",
                    "raw_sent=false",
                    "sanitized_query_only=true",
                ]
            ),
        )

        # The existing research planner now sees only this minimum public query.
        # Attachments remain attached locally for local synthesis/evidence use, but
        # their extracted content is not inserted into the outbound query.
        safe_message = _format_research_message(controls.output_format, safe_query)
        return super().submit(
            safe_message,
            channel=channel,
            sender=sender,
            language=language,
            upload_ids=upload_ids,
            request_mode=mode,
            effort=effort_level,
            conversation_id=conversation_id,
        )


def workspace_ui_capabilities(config: Any) -> dict[str, Any]:
    payload = _BASE_CAPABILITIES(config)
    features = payload.setdefault("features", {})
    upload = features.setdefault("upload", {})
    upload.update(
        {
            "data_boundary": "lan_only",
            "raw_content_public_egress": False,
            "public_query_derivation_from_uploads": False,
        }
    )
    web = features.setdefault("web_search", {})
    web.update(
        {
            "egress_boundary": "sanitized_public_query_only",
            "sensitive_prompt_behavior": "block_warn_require_consent_then_sanitize",
            "raw_prompt_public_egress": False,
            "upload_content_public_egress": False,
            "consent_policy": CONSENT_POLICY_VERSION,
        }
    )
    payload["internet_egress_consent"] = {
        "policy": CONSENT_POLICY_VERSION,
        "ui": _SECURE_CONSENT_UI_VERSION,
        "raw_prompt_public_egress": False,
        "uploads_lan_only": True,
        "explicit_consent_for_sanitized_sensitive_query": True,
    }
    return payload


_CONSENT_SCRIPT = r"""
<script id="workspaceInternetEgressConsent">
(function(){
  if(window.__workspaceEgressConsentInstalled)return;
  window.__workspaceEgressConsentInstalled=true;
  const nativeFetch=window.fetch.bind(window);
  const CHAT_PATH='/api/chat';
  function chatUrl(input){
    try{return new URL(typeof input==='string'?input:input.url,window.location.href).pathname===CHAT_PATH}catch(e){return false}
  }
  function approvalText(d){
    const reasons=(d.reasons||[]).join(', ')||'sensitive/internal data';
    const preview=String(d.sanitized_preview||'');
    return [
      'WorkSpace Internet Egress Safety',
      '',
      'Sensitive/internal information was detected.',
      'Nothing has been sent to the Internet.',
      'Uploaded files remain inside the LAN and are not sent as search content.',
      '',
      'Detected: '+reasons,
      'Removed fields: '+String(d.removed_sensitive_fields||0),
      '',
      'Only this sanitized public query will be sent:',
      preview,
      '',
      'Continue with the sanitized query?'
    ].join('\n');
  }
  window.fetch=async function(input,init){
    const first=await nativeFetch(input,init);
    if(!chatUrl(input)||first.status!==409)return first;
    let d={};
    try{d=await first.clone().json()}catch(e){return first}
    if(d.code!=='INTERNET_EGRESS_CONSENT_REQUIRED'||!d.consent_token)return first;
    if(!window.confirm(approvalText(d)))return first;
    let body={};
    try{body=JSON.parse((init&&init.body)||'{}')}catch(e){return first}
    body.egress_consent_token=d.consent_token;
    const retry={...(init||{}),body:JSON.stringify(body)};
    return nativeFetch(input,retry);
  };
})();
</script>
""".strip()


def _secure_html(document: str) -> str:
    if "workspaceInternetEgressConsent" in document:
        return document
    if "</body>" not in document:
        raise RuntimeError("WorkSpace frontend is missing </body>; consent UI cannot be installed safely")
    return document.replace("</body>", _CONSENT_SCRIPT + "\n</body>", 1)


class SecureApprovedAssetHTTPHandler(legacy.ApprovedAssetHTTPHandler):
    """Current HTTP surface plus pre-submit egress warning/consent."""

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/":
            if not self._private_or_reject():  # noqa: SLF001
                return
            body = _secure_html(legacy.HTML_V17).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def _chat(self) -> None:
        if not self._authorized_local():  # noqa: SLF001
            return
        user = self._current_user()  # noqa: SLF001
        if user is None:
            return
        try:
            payload = self._read_json_large(128 * 1024)  # noqa: SLF001
            message = str(payload.get("message") or "")
            language = str(payload.get("language") or "auto").strip().lower()
            if language not in {"auto", "ja", "vi", "en"}:
                raise ValueError("Unsupported response language")
            fmt = str(payload.get("format") or "source")
            if fmt not in {"source", "pptx", "pdf", "all"}:
                raise ValueError("Unsupported output format")
            mode, effort = legacy._validate_request_options(  # noqa: SLF001
                payload.get("mode"),
                payload.get("effort"),
                self.app.service.orchestrator.config,
            )
            raw_uploads = payload.get("upload_ids") or []
            if not isinstance(raw_uploads, list):
                raise legacy.UploadSecurityError("upload_ids must be an array")
            if len(raw_uploads) > legacy.MAX_UPLOADS_PER_TASK:
                raise legacy.UploadSecurityError(
                    f"At most {legacy.MAX_UPLOADS_PER_TASK} uploads may be attached to one task"
                )
            identity = self._identity(user)  # noqa: SLF001
            upload_ids = legacy._validate_owned_uploads(  # noqa: SLF001
                self.app.service.orchestrator.knowledge_gateway,
                [str(item) for item in raw_uploads],
                identity,
            )
            raw_conversation = str(payload.get("conversation_id") or "").strip()
            prefix = "" if fmt == "source" else f"/{fmt} "
            job = self.app.service.submit(
                prefix + message,
                channel="web",
                sender=identity,
                language=language,
                upload_ids=upload_ids,
                request_mode=mode,
                effort=effort,
                conversation_id=raw_conversation or None,
                egress_consent_token=str(payload.get("egress_consent_token") or ""),
            )
            response = job.public_dict()
            response["conversation_id"] = self.app.service.conversation_for_job(job.job_id)
            self._json(HTTPStatus.ACCEPTED, response)
        except InternetEgressConsentRequired as exc:
            self._json(HTTPStatus.CONFLICT, exc.public_dict())
        except InternetEgressBlocked as exc:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, exc.public_dict())
        except (ValueError, legacy.UploadSecurityError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": legacy.redact_sensitive_text(str(exc))[:800]},
            )


def install_secure_runtime() -> None:
    """Install security wrappers before the legacy consolidated runtime starts."""

    # Defense in depth: the final provider layer refuses any text that is not
    # independently PUBLIC. Declassification/consent happens only in the secure
    # chat service above, so a bypass cannot silently auto-sanitize and egress.
    web_research.sanitize_research_query = strict_public_search_query
    legacy.workspace_ui_capabilities = workspace_ui_capabilities
    legacy.ContinuitySecurityAwareProjectChatService = (
        SecureContinuitySecurityAwareProjectChatService
    )
    legacy.ApprovedAssetHTTPHandler = SecureApprovedAssetHTTPHandler


def main() -> int:
    install_secure_runtime()
    return legacy.main()


if __name__ == "__main__":
    raise SystemExit(main())

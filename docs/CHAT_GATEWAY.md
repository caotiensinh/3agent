# 3Agent LAN Chat, Knowledge Gateway and Telegram

## Purpose

`three-agent-chat` keeps the 3Agent workflow running on the AI workstation while users interact from another device.

- LAN web UI: private/loopback client addresses only.
- Web authentication: generated high-entropy access key; authenticated sessions are bound to the client IP and expire after 12 hours.
- Knowledge Gateway: public-web research plus controlled user uploads.
- Telegram: optional outbound long polling; no inbound Internet port or webhook is required.
- All requests still enter the same `Research -> Presentation -> Human Report` workflow.

## Install on the AI workstation

```bash
cd ~/3agent
git pull --ff-only
./.venv/bin/python -m pip install -e .
bash scripts/install_chat_gateway.sh
```

The installer prints a LAN URL such as `http://192.168.x.x:8787/` and a generated access key. The secret is stored only in `~/.config/3agent/chat.env` with mode `0600` and is not committed to Git.

The service is installed as a systemd user service and enabled for startup:

```bash
systemctl --user status 3agent-chat.service
journalctl --user -u 3agent-chat.service -f
```

## Knowledge Gateway

The web UI can attach up to 8 files to one request. Supported top-level files are:

- `.txt`
- `.md` / `.markdown`
- `.html` / `.htm`
- `.zip`
- `.png`
- `.jpg` / `.jpeg`
- `.webp`

Maximum top-level file size is 16 MiB. Uploads are stored below the local artifact root under `uploads/<upload_id>/` using generated paths rather than user-controlled extraction paths.

### Document processing

Text and Markdown are decoded locally. HTML is reduced to visible text using the same boilerplate-removal parser used by the research pipeline. Script/style/navigation/form content is excluded.

A ZIP is never extracted using original member paths. Members are inspected in memory with limits on entry count, member size, total uncompressed size and compression ratio. Path traversal, encrypted members and suspicious archives fail closed. Nested ZIP files and unsupported members are skipped.

### Image processing

PNG, JPEG and WebP images are format/dimension validated and stored locally. The current default local model is text-oriented, so image semantics are **not** invented or converted into factual evidence. Image content can be enabled later only through an explicitly configured local vision model. Until then, Agent 1 records a diagnostic that an image was attached but not semantically parsed.

### Research source lineage

Uploads are attached to the exact task in SQLite before Agent 1 starts. Agent 1 then collects both upload evidence and public-web evidence through `KnowledgeGateway` and reassigns one stable source sequence:

```text
User upload(s) + public web search
              ↓
        KnowledgeGateway
              ↓
          S1, S2, S3...
              ↓
   Agent 1 verification/quality gate
```

`upload://...` source URLs identify user-provided evidence. They are not treated as independent public verification. Web requests still pass through `InternetGateway`, including public-IP validation, redirect limits, response-size limits and audit logging.

## Web commands

The UI provides language and output selectors. The same controls can be expressed as prefixes:

- `/ja`, `/en`, `/vi`
- `/source`, `/pptx`, `/pdf`, `/all`

Example:

```text
/vi /pptx Nghiên cứu hệ thống AI camera phân tích giao thông tại Nhật Bản.
```

For an attachment-based request, select files with **Attach**, enter the request, then press **Send**. The browser uploads and validates every file first; only accepted upload IDs are attached to the workflow task.

## Human report output

The main chat answer is a reader-facing task report rather than the full daily audit log. Completed tasks can provide:

- Copy answer
- Markdown report
- DOCX report
- PDF report
- PPTX / slide PDF when requested

Raw research JSON, handoff, workflow history and daily evidence stay under the collapsed technical/audit section.

## Telegram

Create the bot with Telegram `@BotFather`, then configure the token locally without putting it in shell history:

```bash
cd ~/3agent
bash scripts/configure_telegram.sh
```

The script hides token input and writes it only to the local `0600` environment file.

If you do not yet know your Telegram numeric user ID:

1. Configure the bot token and leave the allow-list empty.
2. Send `/id` to the bot.
3. Run `bash scripts/configure_telegram.sh` again and add the returned numeric ID.

Only IDs in `THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS` may submit workflow jobs. `/id` and `/whoami` are the only pre-authorization identity helpers.

Telegram uses `getUpdates` long polling. Telegram text uses the same workflow, but file upload through Telegram is intentionally not enabled in this gateway version. This prevents silently routing confidential document attachments through Telegram cloud infrastructure. Use LAN Web Attach for sensitive files.

## Security boundary

The LAN UI is intentionally not a public web service. The HTTP server rejects non-private/non-loopback source addresses and requires the generated access key before chat, uploads or job history can be accessed.

The current LAN MVP uses HTTP rather than TLS. Use it only on a trusted LAN. Do not port-forward TCP 8787 from a router to the public Internet.

Telegram is different from LAN web access: message text necessarily passes through Telegram's cloud before the AI workstation receives it. Therefore do not use Telegram for confidential internal content that is not acceptable to transit Telegram infrastructure. For sensitive work and attachments, use the LAN UI.

All Telegram Bot API requests still pass through the 3Agent `InternetGateway`. Telegram bot tokens are explicitly redacted from audit URLs and exceptions. The Bot API request body is not written to the Internet Gateway audit log.

## Files

Local secrets/config:

```text
~/.config/3agent/chat.env
```

Upload storage:

```text
<data artifact root>/uploads/<upload_id>/
```

Systemd user unit:

```text
~/.config/systemd/user/3agent-chat.service
```

Repository components:

```text
src/three_agent/gateways.py
src/three_agent/knowledge_gateway.py
src/three_agent/chat_gateway_v4.py
scripts/install_chat_gateway.sh
scripts/configure_telegram.sh
tests/test_knowledge_gateway.py
tests/test_chat_gateway_v4.py
```

# 3Agent LAN Chat and Telegram Gateway

## Purpose

`three-agent-chat` keeps the 3Agent workflow running on the AI workstation while users interact from another device.

- LAN web UI: private/loopback client addresses only.
- Web authentication: generated high-entropy access key; authenticated sessions are bound to the client IP and expire after 12 hours.
- Telegram: optional outbound long polling; no inbound Internet port or webhook is required.
- Both channels submit to the same single-worker `Research -> Presentation -> Daily Report` workflow queue.

## Install on the AI workstation

```bash
cd ~/3agent
git pull --ff-only
bash scripts/install_chat_gateway.sh
```

The installer prints a LAN URL such as `http://192.168.x.x:8787/` and a generated access key. The secret is stored only in `~/.config/3agent/chat.env` with mode `0600` and is not committed to Git.

The service is installed as a systemd user service and enabled for startup:

```bash
systemctl --user status 3agent-chat.service
journalctl --user -u 3agent-chat.service -f
```

## Web commands

Normal messages use `source` output, which is suitable for chat. The UI provides language and output selectors. The same controls can be expressed as prefixes:

- `/ja`, `/en`, `/vi`
- `/source`, `/pptx`, `/pdf`, `/all`

Example:

```text
/vi /pptx Nghiên cứu hệ thống AI camera phân tích giao thông tại Nhật Bản.
```

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

Telegram uses `getUpdates` long polling. The gateway calls `deleteWebhook` before polling because Telegram does not allow webhook and long-polling update delivery at the same time.

## Security boundary

The LAN UI is intentionally not a public web service. The HTTP server rejects non-private/non-loopback source addresses and requires the generated access key before chat/job history can be accessed.

The current LAN MVP uses HTTP rather than TLS. Use it only on a trusted LAN. Do not port-forward TCP 8787 from a router to the public Internet. A future hardening step can add LAN TLS with a locally trusted certificate.

Telegram is different from LAN web access: message text necessarily passes through Telegram's cloud before the AI workstation receives it. Therefore do not use Telegram for confidential internal content that is not acceptable to transit Telegram infrastructure. For sensitive work, use the LAN UI.

All Telegram Bot API requests still pass through the 3Agent `InternetGateway`. Telegram bot tokens are explicitly redacted from audit URLs and exceptions. The Bot API request body is not written to the Internet Gateway audit log.

## Files

Local secrets/config:

```text
~/.config/3agent/chat.env
```

Systemd user unit:

```text
~/.config/systemd/user/3agent-chat.service
```

Repository components:

```text
src/three_agent/chat_gateway.py
scripts/install_chat_gateway.sh
scripts/configure_telegram.sh
scripts/test_chat_gateway_contract.sh
tests/test_chat_gateway.py
```

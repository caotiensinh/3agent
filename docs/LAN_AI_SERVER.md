# LAN AI Server Mode

## Recommended deployment

For the intended R&D/test environment, use one Ubuntu workstation as the only AI compute server:

```text
Windows/Linux client PCs
        |
        | browser only
        | HTTP on trusted LAN
        v
Ubuntu AI server
  - 2× RTX 5090
  - NVIDIA driver 590+
  - Ollama / local model
  - Research Agent
  - Presentation Agent
  - Daily Report Agent
  - SQLite + artifacts
  - 3Agent LAN Chat
```

Client PCs do not need Python, Git, Ollama, model weights, GPU drivers, or a local 3Agent installation.

## One-command server setup

On the prepared Ubuntu 24.04.x AI workstation, run as the normal sudo-capable user:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_lan_ai_server.sh | bash
```

This command:

1. downloads the application-only AI-stack setup from GitHub;
2. preserves the already working NVIDIA driver/kernel;
3. validates the two RTX 5090 GPUs;
4. installs/updates Ollama and the configured local model;
5. clones/updates `caotiensinh/3agent`;
6. creates the Python virtual environment and configuration;
7. installs the LAN chat service as a systemd user service;
8. generates a high-entropy web access key;
9. binds the web server to a detected private LAN IPv4 address, not `0.0.0.0`;
10. if UFW is active, attempts to add only a LAN-CIDR-scoped allow rule;
11. verifies Ollama, `3agent smoke`, the chat service, listener and `/api/health`;
12. prints the final browser URL and access key.

Default model:

```text
qwen3:30b
```

Override it without editing source:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_lan_ai_server.sh \
  | THREE_AGENT_MODEL='<ollama-model>' bash
```

## Client use

When the server prints for example:

```text
Web UI:     http://192.168.11.188:8787/
Access key: <generated-secret>
```

on each client PC:

1. open Chrome, Edge, Firefox or another modern browser;
2. browse to the printed URL;
3. enter the printed access key;
4. submit requests.

No client bootstrap is required for normal LAN use.

## Security boundary

The LAN MVP uses HTTP. Use it only on a trusted private LAN. Do not port-forward the chat port from the router to the public Internet.

The server has multiple application controls:

- it binds to a private non-loopback IPv4 address selected from the workstation;
- the HTTP handler rejects non-private source addresses;
- authentication uses a generated access key;
- sessions are bound to the client IP and expire;
- the access key is stored in `~/.config/3agent/chat.env` with mode `0600`;
- the chat service runs as a hardened systemd user service.

If the host firewall is active, the bootstrap only attempts a connected-LAN CIDR rule. It does not intentionally create a world-accessible `8787/tcp` rule.

For confidential internal work, prefer LAN web access over the optional Telegram bridge because Telegram messages transit Telegram infrastructure.

## Operations

Status:

```bash
systemctl --user status 3agent-chat.service
```

Logs:

```bash
journalctl --user -u 3agent-chat.service -f
```

Health:

```bash
curl http://<AI-SERVER-LAN-IP>:8787/api/health
```

Update source/application later:

```bash
3agent-update
```

Then reinstall/restart LAN chat configuration if needed:

```bash
cd ~/3agent
bash scripts/install_chat_gateway.sh
```

## Windows bootstrap

`scripts/bootstrap.ps1` remains supported for development/admin use and CI portability testing. It is **not required** on ordinary LAN client PCs.

For the recommended LAN topology, Windows machines are browser-only clients.

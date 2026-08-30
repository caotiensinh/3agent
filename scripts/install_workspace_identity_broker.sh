#!/usr/bin/env bash
set -Eeuo pipefail

log() { printf '[WorkSpace-Identity-Install] %s\n' "$*"; }
fail() { printf '[WorkSpace-Identity-Install][ERROR] %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run with sudo/root."

ROOT="${WORKSPACE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BROKER_SOURCE="$ROOT/src/three_agent/workspace_identity_broker.py"
CORE_USER="${WORKSPACE_CORE_USER:-${SUDO_USER:-}}"
PUBLIC_BASE="${WORKSPACE_IDENTITY_PUBLIC_BASE_URL:-}"
RETURN_ORIGINS="${WORKSPACE_IDENTITY_ALLOWED_RETURN_ORIGINS:-}"
BROKER_HOST="${WORKSPACE_IDENTITY_BROKER_HOST:-127.0.0.1}"
BROKER_PORT="${WORKSPACE_IDENTITY_BROKER_PORT:-8790}"
REDEEM_PORT="${WORKSPACE_IDENTITY_REDEEM_PORT:-8791}"

[[ -f "$BROKER_SOURCE" ]] || fail "Identity broker source not found: $BROKER_SOURCE"
[[ -n "$CORE_USER" && "$CORE_USER" != "root" ]] || fail "Set WORKSPACE_CORE_USER or run via sudo from the WorkSpace account."
CORE_HOME="$(getent passwd "$CORE_USER" | cut -d: -f6)"
[[ -n "$CORE_HOME" && -d "$CORE_HOME" ]] || fail "Unable to resolve WorkSpace core home."

[[ "$PUBLIC_BASE" == https://* ]] || fail "WORKSPACE_IDENTITY_PUBLIC_BASE_URL must be HTTPS."
[[ -n "$RETURN_ORIGINS" ]] || fail "WORKSPACE_IDENTITY_ALLOWED_RETURN_ORIGINS is required."

providers=()
if [[ -n "${WORKSPACE_GOOGLE_CLIENT_ID:-}" || -n "${WORKSPACE_GOOGLE_CLIENT_SECRET:-}" ]]; then
  [[ -n "${WORKSPACE_GOOGLE_CLIENT_ID:-}" && -n "${WORKSPACE_GOOGLE_CLIENT_SECRET:-}" ]] \
    || fail "Google requires both client ID and client secret."
  providers+=(google)
fi
if [[ -n "${WORKSPACE_GITHUB_CLIENT_ID:-}" || -n "${WORKSPACE_GITHUB_CLIENT_SECRET:-}" ]]; then
  [[ -n "${WORKSPACE_GITHUB_CLIENT_ID:-}" && -n "${WORKSPACE_GITHUB_CLIENT_SECRET:-}" ]] \
    || fail "GitHub requires both client ID and client secret."
  providers+=(github)
fi
if [[ -n "${WORKSPACE_LINE_CHANNEL_ID:-}" || -n "${WORKSPACE_LINE_CHANNEL_SECRET:-}" ]]; then
  [[ -n "${WORKSPACE_LINE_CHANNEL_ID:-}" && -n "${WORKSPACE_LINE_CHANNEL_SECRET:-}" ]] \
    || fail "LINE requires both channel ID and channel secret."
  providers+=(line)
fi
((${#providers[@]} > 0)) || fail "Configure at least one external provider."

IDENTITY_KEY="${WORKSPACE_IDENTITY_KEY:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')}"
REDEEM_KEY="${WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')}"
[[ ${#IDENTITY_KEY} -ge 32 && ${#REDEEM_KEY} -ge 32 ]] || fail "Identity/redeem keys must be at least 32 characters."

for value in "$PUBLIC_BASE" "$RETURN_ORIGINS" "$IDENTITY_KEY" "$REDEEM_KEY" \
  "${WORKSPACE_GOOGLE_CLIENT_ID:-}" "${WORKSPACE_GOOGLE_CLIENT_SECRET:-}" \
  "${WORKSPACE_GITHUB_CLIENT_ID:-}" "${WORKSPACE_GITHUB_CLIENT_SECRET:-}" \
  "${WORKSPACE_LINE_CHANNEL_ID:-}" "${WORKSPACE_LINE_CHANNEL_SECRET:-}"; do
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "Configuration values must not contain newlines."
done

if ! id workspace-auth >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/workspace-auth --create-home --shell /usr/sbin/nologin workspace-auth
fi

install -d -m 0755 -o root -g root /opt/workspace-auth
install -d -m 0750 -o root -g workspace-auth /etc/workspace-auth
install -m 0555 -o root -g root "$BROKER_SOURCE" /opt/workspace-auth/broker.py

ENV_FILE=/etc/workspace-auth/broker.env
umask 077
{
  printf 'WORKSPACE_IDENTITY_PUBLIC_BASE_URL=%s\n' "$PUBLIC_BASE"
  printf 'WORKSPACE_IDENTITY_ALLOWED_RETURN_ORIGINS=%s\n' "$RETURN_ORIGINS"
  printf 'WORKSPACE_IDENTITY_KEY=%s\n' "$IDENTITY_KEY"
  printf 'WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY=%s\n' "$REDEEM_KEY"
  printf 'WORKSPACE_IDENTITY_BROKER_HOST=%s\n' "$BROKER_HOST"
  printf 'WORKSPACE_IDENTITY_BROKER_PORT=%s\n' "$BROKER_PORT"
  printf 'WORKSPACE_IDENTITY_REDEEM_PORT=%s\n' "$REDEEM_PORT"
  [[ -n "${WORKSPACE_GOOGLE_CLIENT_ID:-}" ]] && printf 'WORKSPACE_GOOGLE_CLIENT_ID=%s\nWORKSPACE_GOOGLE_CLIENT_SECRET=%s\n' "$WORKSPACE_GOOGLE_CLIENT_ID" "$WORKSPACE_GOOGLE_CLIENT_SECRET"
  [[ -n "${WORKSPACE_GITHUB_CLIENT_ID:-}" ]] && printf 'WORKSPACE_GITHUB_CLIENT_ID=%s\nWORKSPACE_GITHUB_CLIENT_SECRET=%s\n' "$WORKSPACE_GITHUB_CLIENT_ID" "$WORKSPACE_GITHUB_CLIENT_SECRET"
  [[ -n "${WORKSPACE_LINE_CHANNEL_ID:-}" ]] && printf 'WORKSPACE_LINE_CHANNEL_ID=%s\nWORKSPACE_LINE_CHANNEL_SECRET=%s\n' "$WORKSPACE_LINE_CHANNEL_ID" "$WORKSPACE_LINE_CHANNEL_SECRET"
} >"$ENV_FILE"
chown root:workspace-auth "$ENV_FILE"
chmod 0640 "$ENV_FILE"

cat >/etc/systemd/system/workspace-identity-broker.service <<'UNIT'
[Unit]
Description=WorkSpace external identity-only broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=workspace-auth
Group=workspace-auth
EnvironmentFile=/etc/workspace-auth/broker.env
ExecStart=/usr/bin/python3 /opt/workspace-auth/broker.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

CORE_ENV_DIR="$CORE_HOME/.config/3agent"
CORE_ENV="$CORE_ENV_DIR/chat.env"
install -d -m 0700 -o "$CORE_USER" -g "$CORE_USER" "$CORE_ENV_DIR"
touch "$CORE_ENV"
chown "$CORE_USER:$CORE_USER" "$CORE_ENV"
chmod 0600 "$CORE_ENV"

PROVIDER_CSV="$(IFS=,; printf '%s' "${providers[*]}")"
python3 - "$CORE_ENV" "$PUBLIC_BASE" "$PROVIDER_CSV" "$REDEEM_PORT" "$REDEEM_KEY" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
values = {
    "WORKSPACE_EXTERNAL_AUTH_BROKER_URL": sys.argv[2],
    "WORKSPACE_EXTERNAL_AUTH_PROVIDERS": sys.argv[3],
    "WORKSPACE_EXTERNAL_AUTH_REDEEM_URL": f"http://127.0.0.1:{sys.argv[4]}/redeem",
    "WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY": sys.argv[5],
}
lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
seen = set()
out = []
for line in lines:
    key = line.split("=", 1)[0] if "=" in line else ""
    if key in values:
        if key not in seen:
            out.append(f"{key}={values[key]}")
            seen.add(key)
    else:
        out.append(line)
for key, value in values.items():
    if key not in seen:
        out.append(f"{key}={value}")
path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
PY
chown "$CORE_USER:$CORE_USER" "$CORE_ENV"
chmod 0600 "$CORE_ENV"

systemd-analyze verify /etc/systemd/system/workspace-identity-broker.service
automatic=0
systemctl daemon-reload
systemctl enable --now workspace-identity-broker.service
sleep 2
systemctl is-active --quiet workspace-identity-broker.service || {
  systemctl status workspace-identity-broker.service --no-pager || true
  journalctl -u workspace-identity-broker.service -n 80 --no-pager || true
  fail "Identity broker did not become active."
}

CORE_UID="$(id -u "$CORE_USER")"
if [[ -S "/run/user/$CORE_UID/bus" ]]; then
  if sudo -u "$CORE_USER" XDG_RUNTIME_DIR="/run/user/$CORE_UID" systemctl --user is-active --quiet 3agent-chat.service; then
    sudo -u "$CORE_USER" XDG_RUNTIME_DIR="/run/user/$CORE_UID" systemctl --user restart 3agent-chat.service
    automatic=1
  fi
fi

log "Identity broker installed with providers: $PROVIDER_CSV"
log "Provider callback base: $PUBLIC_BASE"
log "Configure your HTTPS reverse proxy to forward the public base to 127.0.0.1:$BROKER_PORT."
log "Registered callback paths: /auth/callback/google, /auth/callback/github, /auth/callback/line (only configured providers apply)."
if ((automatic)); then
  log "WorkSpace chat service restarted and external login configuration is loaded."
else
  log "Restart WorkSpace chat manually: systemctl --user restart 3agent-chat.service"
fi

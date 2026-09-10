#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${THREE_AGENT_ROOT:-$HOME/3agent}"
CONFIG_DIR="$HOME/.config/3agent"
ENV_FILE="$CONFIG_DIR/chat.env"
SYSTEMD_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SYSTEMD_DIR/3agent-security-monitor.service"
TIMER_FILE="$SYSTEMD_DIR/3agent-security-monitor.timer"
START_SECURITY_TIMER="${THREE_AGENT_START_SECURITY_TIMER:-0}"

log() { printf '[WorkSpace-Security-Lifecycle] %s\n' "$*"; }
fail() { printf '[WorkSpace-Security-Lifecycle][ERROR] %s\n' "$*" >&2; exit 1; }

[[ -d "$ROOT/.git" ]] || fail "Repository not found: $ROOT"
[[ -x "$ROOT/.venv/bin/python" ]] || fail "Python environment missing: $ROOT/.venv"
[[ -f "$ENV_FILE" ]] || fail "Chat environment not found: $ENV_FILE. Run scripts/install_chat_gateway.sh first."

cd "$ROOT"
"$ROOT/.venv/bin/python" -m pip install -e . >/dev/null
[[ -x "$ROOT/.venv/bin/workspace-security-scheduler" ]] || fail "workspace-security-scheduler was not installed"

SECURITY_CONFIG="$(awk -F= '$1=="WORKSPACE_SECURITY_MONITORING_CONFIG" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
[[ -n "$SECURITY_CONFIG" ]] || fail "WORKSPACE_SECURITY_MONITORING_CONFIG is missing from $ENV_FILE"
"$ROOT/.venv/bin/python" - "$SECURITY_CONFIG" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
if not path.is_absolute():
    raise SystemExit("WORKSPACE_SECURITY_MONITORING_CONFIG must be absolute")
if path.is_symlink():
    raise SystemExit("WORKSPACE_SECURITY_MONITORING_CONFIG must not be a symlink")
PY

mkdir -p "$SYSTEMD_DIR"

cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=WorkSpace Security Analyst scheduled read-only monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$ROOT
EnvironmentFile=$ENV_FILE
ExecStart=$ROOT/.venv/bin/workspace-security-scheduler run-scheduled
TimeoutStartSec=15min
TimeoutStopSec=15s
NoNewPrivileges=true
PrivateTmp=true
LockPersonality=true
RestrictSUIDSGID=true
UMask=0077
EOF

cat >"$TIMER_FILE" <<'EOF'
[Unit]
Description=Run WorkSpace Security Analyst monitor once per hour

[Timer]
OnCalendar=*-*-* *:05:00
Persistent=true
AccuracySec=1min
RandomizedDelaySec=0
Unit=3agent-security-monitor.service

[Install]
WantedBy=timers.target
EOF

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze --user verify "$SERVICE_FILE" "$TIMER_FILE" >/dev/null \
    || fail "systemd rejected the Security Analyst lifecycle units"
fi

systemctl --user daemon-reload
systemctl --user disable 3agent-security-monitor.timer >/dev/null 2>&1 || true
systemctl --user stop 3agent-security-monitor.timer >/dev/null 2>&1 || true

if [[ "$START_SECURITY_TIMER" == "1" ]]; then
  systemctl --user enable 3agent-security-monitor.timer >/dev/null
  systemctl --user start 3agent-security-monitor.timer
  log "Hourly Security Analyst timer enabled and started."
else
  log "Lifecycle units installed but timer remains disabled."
  log "To explicitly enable scheduling: THREE_AGENT_START_SECURITY_TIMER=1 bash scripts/install_security_monitor_lifecycle.sh"
fi

log "Authoritative monitoring config: $SECURITY_CONFIG"
log "Scheduler status: $ROOT/.venv/bin/workspace-security-scheduler status"
log "Timer status: systemctl --user status 3agent-security-monitor.timer"
log "No network collection is authorized by this installer; runtime configuration and readiness gates remain authoritative."

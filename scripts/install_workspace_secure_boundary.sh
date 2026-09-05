#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${WORKSPACE_INSTALL_DIR:-$(pwd)}"
VENV="${WORKSPACE_VENV:-${INSTALL_DIR}/.venv}"
CORE_CONFIG_SOURCE="${WORKSPACE_SECURE_CONFIG_SOURCE:-${INSTALL_DIR}/config/workspace.secure.json}"
PUBLIC_CONFIG_SOURCE="${WORKSPACE_PUBLIC_CONFIG_SOURCE:-${INSTALL_DIR}/config/workspace.public-research.json}"
CORE_USER="${WORKSPACE_CORE_USER:-workspace-core}"
PUBLIC_USER="${WORKSPACE_PUBLIC_USER:-workspace-public}"
EGRESS_USER="${WORKSPACE_EGRESS_USER:-workspace-egress}"
IPC_GROUP="${WORKSPACE_IPC_GROUP:-workspace-egress-ipc}"

log() { printf '[WorkSpace] %s\n' "$*"; }
die() { printf '[WorkSpace][ERROR] %s\n' "$*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "Run this boundary installer with sudo/root"
command -v nft >/dev/null 2>&1 || die "nftables is required"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
[[ -x "${VENV}/bin/workspace" ]] || die "workspace CLI not found at ${VENV}/bin/workspace"
[[ -x "${VENV}/bin/workspace-egressd" ]] || die "workspace-egressd not found at ${VENV}/bin/workspace-egressd"
[[ -f "$CORE_CONFIG_SOURCE" ]] || die "secure config not found: $CORE_CONFIG_SOURCE"
[[ -f "$PUBLIC_CONFIG_SOURCE" ]] || die "public research config not found: $PUBLIC_CONFIG_SOURCE"

getent group "$IPC_GROUP" >/dev/null || groupadd --system "$IPC_GROUP"
id "$CORE_USER" >/dev/null 2>&1 || useradd --system --home-dir /var/lib/workspace --shell /usr/sbin/nologin "$CORE_USER"
id "$PUBLIC_USER" >/dev/null 2>&1 || useradd --system --home-dir /var/lib/workspace-public --shell /usr/sbin/nologin "$PUBLIC_USER"
id "$EGRESS_USER" >/dev/null 2>&1 || useradd --system --home-dir /var/lib/workspace-egress --shell /usr/sbin/nologin "$EGRESS_USER"

# Deliberately do NOT add workspace-core to the egress IPC group.
usermod -a -G "$IPC_GROUP" "$PUBLIC_USER"
usermod -a -G "$IPC_GROUP" "$EGRESS_USER"

CORE_UID="$(id -u "$CORE_USER")"
PUBLIC_UID="$(id -u "$PUBLIC_USER")"
EGRESS_UID="$(id -u "$EGRESS_USER")"

install -d -o "$CORE_USER" -g "$CORE_USER" -m 0700 /var/lib/workspace /var/lib/workspace/data
install -d -o "$PUBLIC_USER" -g "$PUBLIC_USER" -m 0700 /var/lib/workspace-public /var/lib/workspace-public/data
install -d -o "$EGRESS_USER" -g "$IPC_GROUP" -m 0750 /var/log/workspace
install -d -o root -g root -m 0755 /etc/workspace
install -o root -g "$CORE_USER" -m 0640 "$CORE_CONFIG_SOURCE" /etc/workspace/workspace.secure.json
install -o root -g "$IPC_GROUP" -m 0640 "$PUBLIC_CONFIG_SOURCE" /etc/workspace/workspace.public-research.json

cat >/etc/systemd/system/workspace-egress.service <<EOF
[Unit]
Description=WorkSpace constrained public Internet egress broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${EGRESS_USER}
Group=${IPC_GROUP}
ExecStart=${VENV}/bin/workspace-egressd --config /etc/workspace/workspace.public-research.json --socket /run/workspace/egress.sock --allow-uid ${PUBLIC_UID}
Restart=on-failure
RestartSec=2
RuntimeDirectory=workspace
RuntimeDirectoryMode=0770
LogsDirectory=workspace
LogsDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/run/workspace /var/log/workspace
InaccessiblePaths=/var/lib/workspace /var/lib/workspace-public
UMask=007

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/workspace/workspace-core.nft <<EOF
# WorkSpace high-assurance output policy.
table inet workspace_core {
  chain output {
    type filter hook output priority -50; policy accept;

    meta skuid ${CORE_UID} ip daddr 127.0.0.1 tcp dport 11434-11436 accept
    meta skuid ${CORE_UID} ip6 daddr ::1 tcp dport 11434-11436 accept
    meta skuid ${CORE_UID} counter reject

    meta skuid ${PUBLIC_UID} ip daddr 127.0.0.1 tcp dport 11434-11436 accept
    meta skuid ${PUBLIC_UID} ip6 daddr ::1 tcp dport 11434-11436 accept
    meta skuid ${PUBLIC_UID} counter reject

    meta skuid ${EGRESS_UID} ip daddr 127.0.0.53 udp dport 53 accept
    meta skuid ${EGRESS_UID} ip daddr 127.0.0.53 tcp dport 53 accept
    meta skuid ${EGRESS_UID} ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } reject
    meta skuid ${EGRESS_UID} ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } reject
    meta skuid ${EGRESS_UID} tcp dport 443 accept
    meta skuid ${EGRESS_UID} counter reject
  }
}
EOF

install -d -m 0755 /usr/local/lib/workspace
cat >/usr/local/lib/workspace/apply-network-lockdown.sh <<'SH2'
#!/usr/bin/env bash
set -Eeuo pipefail
nft delete table inet workspace_core 2>/dev/null || true
exec nft -f /etc/workspace/workspace-core.nft
SH2
chmod 0755 /usr/local/lib/workspace/apply-network-lockdown.sh

cat >/etc/systemd/system/workspace-network-lockdown.service <<'EOF'
[Unit]
Description=WorkSpace Core/Public direct-egress deny policy
Before=workspace-egress.service
After=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/workspace/apply-network-lockdown.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat >/usr/local/lib/workspace/core-run <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
cd $(printf '%q' "$INSTALL_DIR")
export WORKSPACE_CONFIG=/etc/workspace/workspace.secure.json
exec ${VENV}/bin/workspace "\$@"
EOF
chmod 0755 /usr/local/lib/workspace/core-run

cat >/usr/local/lib/workspace/public-run <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
cd $(printf '%q' "$INSTALL_DIR")
export WORKSPACE_CONFIG=/etc/workspace/workspace.public-research.json
exec ${VENV}/bin/workspace "\$@"
EOF
chmod 0755 /usr/local/lib/workspace/public-run

cat >/usr/local/bin/workspace-secure <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec sudo -u $(printf '%q' "$CORE_USER") -H /usr/local/lib/workspace/core-run "\$@"
EOF
chmod 0755 /usr/local/bin/workspace-secure

cat >/usr/local/bin/workspace-public <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec sudo -u $(printf '%q' "$PUBLIC_USER") -H /usr/local/lib/workspace/public-run "\$@"
EOF
chmod 0755 /usr/local/bin/workspace-public

cat >/etc/sudoers.d/workspace-core <<EOF
%sudo ALL=(${CORE_USER}) NOPASSWD: /usr/local/lib/workspace/core-run *
%sudo ALL=(${PUBLIC_USER}) NOPASSWD: /usr/local/lib/workspace/public-run *
EOF
chmod 0440 /etc/sudoers.d/workspace-core
visudo -cf /etc/sudoers.d/workspace-core >/dev/null

systemctl daemon-reload
systemctl enable --now workspace-network-lockdown.service
systemctl enable --now workspace-egress.service

log "High-assurance boundary installed."
log "Confidential Core UID=${CORE_UID}: localhost Ollama only; no broker membership and no Internet/LAN egress."
log "Public Research UID=${PUBLIC_UID}: separate DB/data, localhost Ollama only, broker IPC allowed, no confidential-data permission."
log "Egress UID=${EGRESS_UID}: public TCP/443 + local DNS only; both WorkSpace data roots inaccessible."
log "Confidential command: workspace-secure <command>"
log "Public research command: workspace-public <command>"

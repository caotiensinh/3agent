#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${WORKSPACE_INSTALL_DIR:-$(pwd)}"
VENV="${WORKSPACE_VENV:-${INSTALL_DIR}/.venv}"
CORE_USER="${WORKSPACE_CORE_USER:-workspace-core}"
PUBLIC_USER="${WORKSPACE_PUBLIC_USER:-workspace-public}"
IMPORT_USER="${WORKSPACE_IMPORT_USER:-workspace-import}"
EXPORT_GROUP="${WORKSPACE_PUBLIC_EXPORT_GROUP:-workspace-public-export}"
KNOWLEDGE_GROUP="${WORKSPACE_PUBLIC_KNOWLEDGE_GROUP:-workspace-public-knowledge}"
EXPORT_ROOT="${WORKSPACE_PUBLIC_EXPORT_ROOT:-/var/spool/workspace-public-export}"
KNOWLEDGE_ROOT="${WORKSPACE_PUBLIC_KNOWLEDGE_ROOT:-/var/lib/workspace-knowledge-public}"

log() { printf '[WorkSpace-Knowledge] %s\n' "$*"; }
die() { printf '[WorkSpace-Knowledge][ERROR] %s\n' "$*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "Run with sudo/root"
command -v nft >/dev/null 2>&1 || die "nftables is required"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v realpath >/dev/null 2>&1 || die "realpath is required"
[[ -x "${VENV}/bin/workspace-knowledge" ]] || die "workspace-knowledge CLI not found"
id "$CORE_USER" >/dev/null 2>&1 || die "Core identity is missing; install secure boundary first"
id "$PUBLIC_USER" >/dev/null 2>&1 || die "Public identity is missing; install secure boundary first"

getent group "$EXPORT_GROUP" >/dev/null || groupadd --system "$EXPORT_GROUP"
getent group "$KNOWLEDGE_GROUP" >/dev/null || groupadd --system "$KNOWLEDGE_GROUP"
id "$IMPORT_USER" >/dev/null 2>&1 || useradd --system --home-dir "$KNOWLEDGE_ROOT" --shell /usr/sbin/nologin "$IMPORT_USER"

# Explicit capabilities:
# - Public can write only the export spool.
# - Importer can read the export spool and write only the public knowledge mirror.
# - Core can read the public knowledge mirror.
# - No one gains membership in another zone's private data group.
usermod -a -G "$EXPORT_GROUP" "$PUBLIC_USER"
usermod -a -G "$EXPORT_GROUP" "$IMPORT_USER"
usermod -a -G "$KNOWLEDGE_GROUP" "$IMPORT_USER"
usermod -a -G "$KNOWLEDGE_GROUP" "$CORE_USER"

install -d -o "$PUBLIC_USER" -g "$EXPORT_GROUP" -m 2750 "$EXPORT_ROOT"
install -d -o "$IMPORT_USER" -g "$KNOWLEDGE_GROUP" -m 2750 "$KNOWLEDGE_ROOT"

# Defense in depth: the network-capable broker cannot inspect either side of
# the public-knowledge handoff even if ordinary filesystem permissions change.
install -d -m 0755 /etc/systemd/system/workspace-egress.service.d
cat >/etc/systemd/system/workspace-egress.service.d/knowledge-plane.conf <<EOF
[Service]
InaccessiblePaths=${EXPORT_ROOT} ${KNOWLEDGE_ROOT}
EOF

IMPORT_UID="$(id -u "$IMPORT_USER")"

cat >/etc/workspace/workspace-importer.nft <<EOF
# WorkSpace public knowledge importer: zero IP network authority.
table inet workspace_importer {
  chain output {
    type filter hook output priority -45; policy accept;
    meta skuid ${IMPORT_UID} counter reject
  }
}
EOF

install -d -m 0755 /usr/local/lib/workspace
cat >/usr/local/lib/workspace/apply-importer-lockdown.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
nft delete table inet workspace_importer 2>/dev/null || true
exec nft -f /etc/workspace/workspace-importer.nft
EOF
chmod 0755 /usr/local/lib/workspace/apply-importer-lockdown.sh

cat >/etc/systemd/system/workspace-importer-lockdown.service <<'EOF'
[Unit]
Description=WorkSpace public-knowledge importer network deny
After=network-pre.target
Before=workspace-egress.service

[Service]
Type=oneshot
ExecStart=/usr/local/lib/workspace/apply-importer-lockdown.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat >/usr/local/lib/workspace/knowledge-export-run <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "\$#" -eq 1 ]] || { echo "usage: knowledge-export-run RESEARCH_JSON" >&2; exit 2; }
candidate="\$(realpath -e -- "\$1")"
root="\$(realpath -e -- /var/lib/workspace-public/data)"
case "\$candidate" in
  "\$root"/*) ;;
  *) echo "research artifact must be inside /var/lib/workspace-public/data" >&2; exit 3 ;;
esac
cd $(printf '%q' "$INSTALL_DIR")
exec ${VENV}/bin/workspace-knowledge export \
  --research-json "\$candidate" \
  --outbox $(printf '%q' "$EXPORT_ROOT")
EOF
chmod 0755 /usr/local/lib/workspace/knowledge-export-run

cat >/usr/local/lib/workspace/knowledge-import-run <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "\$#" -eq 1 ]] || { echo "usage: knowledge-import-run BUNDLE_DIR" >&2; exit 2; }
candidate="\$(realpath -e -- "\$1")"
root="\$(realpath -e -- $(printf '%q' "$EXPORT_ROOT"))"
case "\$candidate" in
  "\$root"/kb_*) ;;
  *) echo "bundle must be inside the public export spool" >&2; exit 3 ;;
esac
cd $(printf '%q' "$INSTALL_DIR")
exec ${VENV}/bin/workspace-knowledge import \
  --bundle "\$candidate" \
  --knowledge-root $(printf '%q' "$KNOWLEDGE_ROOT")
EOF
chmod 0755 /usr/local/lib/workspace/knowledge-import-run

cat >/usr/local/lib/workspace/knowledge-search-run <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
cd $(printf '%q' "$INSTALL_DIR")
export WORKSPACE_PUBLIC_KNOWLEDGE_ROOT=$(printf '%q' "$KNOWLEDGE_ROOT")
exec ${VENV}/bin/workspace-knowledge search "\$@"
EOF
chmod 0755 /usr/local/lib/workspace/knowledge-search-run

cat >/usr/local/lib/workspace/knowledge-pack-run <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
cd $(printf '%q' "$INSTALL_DIR")
export WORKSPACE_PUBLIC_KNOWLEDGE_ROOT=$(printf '%q' "$KNOWLEDGE_ROOT")
exec ${VENV}/bin/workspace-knowledge pack "\$@"
EOF
chmod 0755 /usr/local/lib/workspace/knowledge-pack-run

cat >/usr/local/bin/workspace-knowledge-export <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec sudo -u $(printf '%q' "$PUBLIC_USER") -H /usr/local/lib/workspace/knowledge-export-run "\$@"
EOF
chmod 0755 /usr/local/bin/workspace-knowledge-export

cat >/usr/local/bin/workspace-knowledge-import <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec sudo -u $(printf '%q' "$IMPORT_USER") -H /usr/local/lib/workspace/knowledge-import-run "\$@"
EOF
chmod 0755 /usr/local/bin/workspace-knowledge-import

cat >/usr/local/bin/workspace-knowledge-search <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec sudo -u $(printf '%q' "$CORE_USER") -H /usr/local/lib/workspace/knowledge-search-run "\$@"
EOF
chmod 0755 /usr/local/bin/workspace-knowledge-search

cat >/usr/local/bin/workspace-knowledge-pack <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec sudo -u $(printf '%q' "$CORE_USER") -H /usr/local/lib/workspace/knowledge-pack-run "\$@"
EOF
chmod 0755 /usr/local/bin/workspace-knowledge-pack

cat >/etc/sudoers.d/workspace-knowledge <<EOF
%sudo ALL=(${PUBLIC_USER}) NOPASSWD: /usr/local/lib/workspace/knowledge-export-run *
%sudo ALL=(${IMPORT_USER}) NOPASSWD: /usr/local/lib/workspace/knowledge-import-run *
%sudo ALL=(${CORE_USER}) NOPASSWD: /usr/local/lib/workspace/knowledge-search-run *
%sudo ALL=(${CORE_USER}) NOPASSWD: /usr/local/lib/workspace/knowledge-pack-run *
EOF
chmod 0440 /etc/sudoers.d/workspace-knowledge
visudo -cf /etc/sudoers.d/workspace-knowledge >/dev/null

systemctl daemon-reload
systemctl enable --now workspace-importer-lockdown.service
systemctl restart workspace-egress.service

log "Installed one-way public knowledge plane."
log "Public export spool: ${EXPORT_ROOT}"
log "Core-readable public mirror: ${KNOWLEDGE_ROOT}"
log "Importer UID=${IMPORT_UID}: all IP network traffic rejected."
log "Export: workspace-knowledge-export <public-research.json>"
log "Approve/import: workspace-knowledge-import <bundle-dir>"
log "Search locally: workspace-knowledge-search --query '...'"

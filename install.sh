#!/usr/bin/env bash
set -Eeuo pipefail

CANONICAL_REPOSITORY="caotiensinh/3agent"
SOURCE_REF="${WORKSPACE_SOURCE_REF:-${THREE_AGENT_REPO_REF:-main}}"
TRACKING_REF="${THREE_AGENT_REPO_REF:-$SOURCE_REF}"
EXPECTED_SHA256="${WORKSPACE_INSTALLER_SHA256:-}"
SELF_TEST=0
TMP_ENTRYPOINT=""

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    *) printf '[WorkSpace Installer][ERROR] Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[WorkSpace Installer] %s\n' "$*"; }
die() { printf '[WorkSpace Installer][ERROR] %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "$TMP_ENTRYPOINT" && -f "$TMP_ENTRYPOINT" ]]; then
    rm -f "$TMP_ENTRYPOINT"
  fi
}
trap cleanup EXIT

validate_ref() {
  local value="$1"
  [[ -n "$value" ]] || die "Source ref is empty"
  [[ "$value" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Source ref contains unsupported characters: $value"
  [[ "$value" != /* && "$value" != *".."* ]] || die "Source ref is not safe: $value"
}

validate_hash() {
  [[ -z "$EXPECTED_SHA256" || "$EXPECTED_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] \
    || die "WORKSPACE_INSTALLER_SHA256 must be a 64-character SHA-256 value"
}

validate_ref "$SOURCE_REF"
validate_ref "$TRACKING_REF"
validate_hash

if [[ "$SELF_TEST" == "1" ]]; then
  log "One-command Ubuntu entrypoint self-test PASS"
  log "Repository: ${CANONICAL_REPOSITORY}"
  log "Source ref: ${SOURCE_REF}"
  log "Tracking ref: ${TRACKING_REF}"
  exit 0
fi

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v bash >/dev/null 2>&1 || die "bash is required"

ENTRYPOINT_URL="https://raw.githubusercontent.com/${CANONICAL_REPOSITORY}/${SOURCE_REF}/scripts/deploy_ubuntu_pc.sh"
BOOTSTRAP_URL="https://raw.githubusercontent.com/${CANONICAL_REPOSITORY}/${SOURCE_REF}/scripts/bootstrap.sh"
TMP_ENTRYPOINT="$(mktemp)"

log "Downloading reviewed WorkSpace deployment entrypoint from ${SOURCE_REF}"
curl -fsSL --retry 3 --connect-timeout 15 "$ENTRYPOINT_URL" -o "$TMP_ENTRYPOINT"
bash -n "$TMP_ENTRYPOINT" || die "Downloaded deployment entrypoint failed Bash syntax validation"

if [[ -n "$EXPECTED_SHA256" ]]; then
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required when WORKSPACE_INSTALLER_SHA256 is set"
  ACTUAL_SHA256="$(sha256sum "$TMP_ENTRYPOINT" | awk '{print $1}')"
  [[ "${ACTUAL_SHA256,,}" == "${EXPECTED_SHA256,,}" ]] \
    || die "Deployment entrypoint checksum mismatch"
  log "Deployment entrypoint SHA-256 verification PASS"
fi

export THREE_AGENT_REPO_URL="https://github.com/${CANONICAL_REPOSITORY}.git"
export THREE_AGENT_REPO_REF="$TRACKING_REF"
export THREE_AGENT_BOOTSTRAP_URL="$BOOTSTRAP_URL"

bash "$TMP_ENTRYPOINT"

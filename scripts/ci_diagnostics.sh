#!/usr/bin/env bash
# shellcheck shell=bash

# CI-only diagnostics helpers. These functions intentionally avoid dumping the
# full environment, Git remotes, configuration contents, or command arguments
# because those surfaces can contain credentials or other sensitive values.

ci_diag_dir() {
  printf '%s\n' "${CI_DIAGNOSTIC_DIR:-${RUNNER_TEMP:-/tmp}/three-agent-ci-diagnostics}"
}

ci_diag_safe_name() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_'
}

ci_diag_snapshot() {
  local label="${1:-snapshot}"
  local dir
  dir="$(ci_diag_dir)"
  mkdir -p "$dir"

  echo "::group::3Agent diagnostic snapshot: ${label}"
  printf 'diagnostic_label=%s\n' "$label"
  printf 'timestamp_utc=%s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  printf 'cwd=%s\n' "$PWD"
  printf 'runner_os=%s\n' "${RUNNER_OS:-unknown}"
  printf 'runner_arch=%s\n' "${RUNNER_ARCH:-unknown}"
  printf 'github_workflow=%s\n' "${GITHUB_WORKFLOW:-unknown}"
  printf 'github_job=%s\n' "${GITHUB_JOB:-unknown}"
  printf 'github_ref_name=%s\n' "${GITHUB_REF_NAME:-unknown}"
  printf 'github_head_ref=%s\n' "${GITHUB_HEAD_REF:-unknown}"
  printf 'github_sha=%s\n' "${GITHUB_SHA:-unknown}"

  uname -a || true
  if [[ -r /etc/os-release ]]; then
    grep -E '^(NAME|VERSION|ID|VERSION_ID)=' /etc/os-release || true
  fi

  if command -v git >/dev/null 2>&1; then
    printf 'git_path=%s\n' "$(command -v git)"
    git --version || true
    printf 'git_head=%s\n' "$(git rev-parse HEAD 2>/dev/null || printf unknown)"
    git status --short --branch || true
  fi

  local py
  for py in python python3; do
    if command -v "$py" >/dev/null 2>&1; then
      printf '%s_path=%s\n' "$py" "$(command -v "$py")"
      "$py" --version 2>&1 || true
    fi
  done

  if command -v python >/dev/null 2>&1; then
    python -m pip --version 2>&1 || true
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m pip --version 2>&1 || true
  fi

  df -h . 2>/dev/null || true
  if command -v free >/dev/null 2>&1; then free -h || true; fi
  echo "::endgroup::"
}

ci_run_logged() {
  if [[ "$#" -lt 2 ]]; then
    echo '[3Agent][CI-DIAG][ERROR] ci_run_logged requires LABEL COMMAND [ARG...]' >&2
    return 2
  fi

  local label="$1"
  shift
  local dir safe log rc
  dir="$(ci_diag_dir)"
  safe="$(ci_diag_safe_name "$label")"
  log="${dir}/${safe}.log"
  mkdir -p "$dir"

  echo "::group::3Agent command log: ${label}"
  printf '[3Agent][CI-DIAG] stage=%s executable=%s argument_count=%s log=%s\n' \
    "$label" "$1" "$(( $# - 1 ))" "$log"

  set +e
  PYTHONFAULTHANDLER=1 PYTHONUNBUFFERED=1 "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e

  printf '[3Agent][CI-DIAG] stage=%s exit_code=%s\n' "$label" "$rc"
  echo "::endgroup::"

  if [[ "$rc" -ne 0 ]]; then
    echo "::error::3Agent diagnostic stage '${label}' failed with exit code ${rc}"
  fi
  return "$rc"
}

ci_failure_snapshot() {
  local label="${1:-failure}"
  echo "::group::3Agent failure snapshot: ${label}"
  printf 'failure_label=%s\n' "$label"
  printf 'timestamp_utc=%s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  if command -v git >/dev/null 2>&1; then
    printf 'git_head=%s\n' "$(git rev-parse HEAD 2>/dev/null || printf unknown)"
    git status --short --branch || true
  fi

  local path
  for path in \
    "${THREE_AGENT_INSTALL_DIR:-}" \
    "${THREE_AGENT_BIN_DIR:-}" \
    "${THREE_AGENT_RELEASES_DIR:-}" \
    "${THREE_AGENT_STATE_DIR:-}"
  do
    [[ -n "$path" ]] || continue
    printf '%s\n' "--- path: ${path} ---"
    if [[ -e "$path" ]]; then
      find "$path" -maxdepth 3 -mindepth 1 \
        ! -name '.git' \
        ! -path '*/.git/*' \
        ! -name 'local.json' \
        ! -name '*.credentials' \
        -printf '%y %p\n' 2>/dev/null | sort | head -n 400 || true
    else
      echo '(missing)'
    fi
  done
  echo "::endgroup::"
}

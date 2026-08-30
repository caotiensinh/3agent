#!/usr/bin/env bash
# Register a pool of GitHub Actions self-hosted runner instances on ONE physical machine,
# split into two lanes so lightweight CI work stops queueing behind whatever else is
# running, while GPU-bound work stays exclusive (docs/WORKSPACE_RUNNER_POOL.md).
#
#   general lane  (default 7 instances, labels: self-hosted,general)
#     For jobs that never touch the GPUs or Ollama: shellcheck, bash contract tests,
#     `python -m unittest`, packaging/lint checks. Safe to run many at once on a
#     32GB-RAM host because each instance is CPU/IO-bound and lightweight.
#
#   gpu lane      (default 1 instance, labels: self-hosted,gpu)
#     For jobs that run live Ollama generation or touch nvidia-smi/systemd GPU state
#     (scripts/setup_ai_stack_ubuntu2404.sh, closure/benchmark workflows). Kept to a
#     small, deliberately non-parallel pool: running several GPU-heavy CI jobs at once
#     on this exact host (2x RTX 5090, 32GB RAM) would contend for VRAM/RAM and corrupt
#     the clean-measurement assumption the D3/D7 benchmark evidence in this repo depends
#     on. Workflows in this lane are expected to additionally set a shared
#     `concurrency: group: gpu-rtx5090-exclusive` so true parallel GPU execution never
#     happens regardless of how many gpu-labeled runners exist.
#
# This script only automates the repetitive part (download once, register N times,
# install N systemd services). It never fabricates a runner version, download URL, or
# checksum: --tarball-url, --tarball-sha256, and --token must be pasted from this
# repository's own "Settings -> Actions -> Runners -> New self-hosted runner" page,
# which GitHub generates specifically for this repo and the current runner release.
set -Eeuo pipefail

REPO_URL="${RUNNER_POOL_REPO_URL:-https://github.com/caotiensinh/3agent}"
BASE_DIR="${RUNNER_POOL_BASE_DIR:-$HOME/actions-runner-pool}"
GENERAL_COUNT="${RUNNER_POOL_GENERAL_COUNT:-7}"
GPU_COUNT="${RUNNER_POOL_GPU_COUNT:-1}"
TOKEN=""
TARBALL_URL=""
TARBALL_SHA256=""
ACTION="setup"
SELF_TEST=0

log() { printf '[RunnerPool] %s\n' "$*"; }
warn() { printf '[RunnerPool][WARN] %s\n' "$*" >&2; }
die() { printf '[RunnerPool][ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  setup_runner_pool.sh --token <REG_TOKEN> --tarball-url <URL> --tarball-sha256 <SHA256> \
      [--repo-url URL] [--base-dir DIR] [--general-count N] [--gpu-count N]
  setup_runner_pool.sh --teardown --token <REMOVE_TOKEN> [--base-dir DIR]
  setup_runner_pool.sh --self-test

--token, --tarball-url and --tarball-sha256 must come from this repository's own
GitHub "Settings -> Actions -> Runners -> New self-hosted runner" page (Linux x64).
That page generates the current runner release URL/checksum and a short-lived
registration token scoped to this exact repo; this script never guesses them.
EOF
}

is_nonneg_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    --teardown) ACTION="teardown" ;;
    --token=*) TOKEN="${arg#*=}" ;;
    --tarball-url=*) TARBALL_URL="${arg#*=}" ;;
    --tarball-sha256=*) TARBALL_SHA256="${arg#*=}" ;;
    --repo-url=*) REPO_URL="${arg#*=}" ;;
    --base-dir=*) BASE_DIR="${arg#*=}" ;;
    --general-count=*) GENERAL_COUNT="${arg#*=}" ;;
    --gpu-count=*) GPU_COUNT="${arg#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $arg (see --help)" ;;
  esac
done

validate_settings() {
  [[ -n "$REPO_URL" ]] || die "--repo-url must not be empty"
  [[ "$REPO_URL" == https://github.com/* ]] || die "--repo-url must be an https://github.com/... URL"
  is_nonneg_int "$GENERAL_COUNT" || die "--general-count must be a non-negative integer"
  is_nonneg_int "$GPU_COUNT" || die "--gpu-count must be a non-negative integer"
  (( GENERAL_COUNT + GPU_COUNT >= 1 )) || die "At least one runner instance must be requested"
  (( GENERAL_COUNT + GPU_COUNT <= 32 )) || die "Refusing to register more than 32 instances at once"
}

if [[ "$SELF_TEST" == "1" ]]; then
  validate_settings
  log "Runner-pool self-test PASS (general=$GENERAL_COUNT gpu=$GPU_COUNT)"
  exit 0
fi

validate_settings
[[ -n "$TOKEN" ]] || die "--token is required (paste it from the GitHub New-runner page)"

instance_names() {
  local i
  for ((i = 1; i <= GENERAL_COUNT; i++)); do printf 'general-%d self-hosted,general\n' "$i"; done
  for ((i = 1; i <= GPU_COUNT; i++)); do printf 'gpu-%d self-hosted,gpu\n' "$i"; done
}

if [[ "$ACTION" == "teardown" ]]; then
  [[ -d "$BASE_DIR" ]] || die "Nothing to tear down: $BASE_DIR does not exist"
  while read -r name _labels; do
    dir="$BASE_DIR/$name"
    [[ -d "$dir" ]] || continue
    log "Removing instance $name"
    if [[ -x "$dir/svc.sh" ]]; then
      (cd "$dir" && { sudo ./svc.sh stop || true; sudo ./svc.sh uninstall || true; })
    fi
    if [[ -x "$dir/config.sh" && -f "$dir/.runner" ]]; then
      (cd "$dir" && ./config.sh remove --unattended --token "$TOKEN") \
        || warn "GitHub-side removal for $name failed; remove it manually from the Runners page"
    fi
    rm -rf "$dir"
  done < <(instance_names)
  log "Teardown complete. $BASE_DIR left in place (only registered instance dirs were removed)."
  exit 0
fi

[[ -n "$TARBALL_URL" ]] || die "--tarball-url is required (paste it from the GitHub New-runner page)"
[[ -n "$TARBALL_SHA256" ]] || die "--tarball-sha256 is required (paste it from the GitHub New-runner page)"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v sudo >/dev/null 2>&1 || die "sudo is required to install the runner systemd services"

mkdir -p "$BASE_DIR/.cache"
CACHE_TARBALL="$BASE_DIR/.cache/$(basename "$TARBALL_URL")"

if [[ -f "$CACHE_TARBALL" ]] \
    && echo "${TARBALL_SHA256}  ${CACHE_TARBALL}" | sha256sum -c - >/dev/null 2>&1; then
  log "Reusing already-downloaded, checksum-verified runner tarball: $CACHE_TARBALL"
else
  log "Downloading runner release once for reuse across all $((GENERAL_COUNT + GPU_COUNT)) instances"
  curl -fsSL -o "$CACHE_TARBALL" "$TARBALL_URL"
  echo "${TARBALL_SHA256}  ${CACHE_TARBALL}" | sha256sum -c - \
    || die "Checksum mismatch for $CACHE_TARBALL; refusing to extract an unverified runner binary"
fi

setup_instance() {
  local name="$1" labels="$2"
  local dir="$BASE_DIR/$name"
  if [[ -f "$dir/.runner" ]]; then
    log "Instance $name already registered; skipping config.sh (idempotent)."
  else
    mkdir -p "$dir"
    tar xzf "$CACHE_TARBALL" -C "$dir"
    (
      cd "$dir"
      ./config.sh --unattended --replace \
        --url "$REPO_URL" \
        --token "$TOKEN" \
        --name "aiserver-${name}" \
        --labels "$labels" \
        --work "_work"
    )
  fi
  if [[ -x "$dir/svc.sh" ]]; then
    if (cd "$dir" && sudo ./svc.sh status >/dev/null 2>&1); then
      log "Service for $name already installed; ensuring it is started."
      (cd "$dir" && sudo ./svc.sh start) || true
    else
      (cd "$dir" && sudo ./svc.sh install && sudo ./svc.sh start)
    fi
  fi
  log "Instance $name ready (labels: $labels)"
}

while read -r name labels; do
  setup_instance "$name" "$labels"
done < <(instance_names)

log "FINAL PASS: $GENERAL_COUNT general + $GPU_COUNT gpu runner instance(s) registered under $BASE_DIR"
log "Verify on GitHub: repository Settings -> Actions -> Runners should list aiserver-general-* and aiserver-gpu-*"
log "Point lightweight CI at 'runs-on: [self-hosted, general]' and GPU-bound workflows at"
log "'runs-on: [self-hosted, gpu]' plus a shared 'concurrency: group: gpu-rtx5090-exclusive'."

#!/usr/bin/env bash
# One-command bootstrap for a pool of GitHub Actions self-hosted runner instances on
# ONE physical machine, split into two lanes so lightweight CI work stops queueing
# behind whatever else is running, while GPU-bound work stays exclusive
# (docs/WORKSPACE_RUNNER_POOL.md).
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
# Nothing about the runner release is hardcoded: the current linux-x64 runner
# version/URL is resolved live from GitHub's public releases API on every run, so this
# script is never stale and never guesses a version on the caller's behalf. The
# registration token is short-lived and repo-scoped by design; this script mints it
# itself via the GitHub API from a Personal Access Token (never printed, never written
# to disk) instead of asking you to open the GitHub UI and copy/paste it. A
# --token/--tarball-url/--tarball-sha256 manual path remains for anyone who prefers to
# audit exactly what they are pasting from the "New self-hosted runner" UI page.
set -Eeuo pipefail

REPO_URL="${RUNNER_POOL_REPO_URL:-https://github.com/caotiensinh/3agent}"
BASE_DIR="${RUNNER_POOL_BASE_DIR:-$HOME/actions-runner-pool}"
GENERAL_COUNT="${RUNNER_POOL_GENERAL_COUNT:-7}"
GPU_COUNT="${RUNNER_POOL_GPU_COUNT:-1}"
GH_PAT="${GH_PAT:-${GITHUB_TOKEN:-}}"
TOKEN=""
REMOVE_TOKEN=""
TARBALL_URL=""
TARBALL_SHA256=""
ADOPT_EXISTING_DIR=""
ADOPT_EXISTING_SET=0
DEFAULT_EXISTING_DIR="$HOME/actions-runner"
ACTION="setup"
SELF_TEST=0

# Every curl call below carries an explicit connect/overall timeout. Without one, a
# DNS/network hiccup (or, as observed, some networks not failing fast on a clearly
# invalid host) hangs `curl -fsSL` indefinitely instead of erroring, since curl has no
# default timeout of its own. API calls are small and fast; only the tarball download
# gets a longer overall budget since it is a real multi-hundred-MB transfer.
CURL_API_OPTS=(--connect-timeout 10 --max-time 20)
CURL_DOWNLOAD_OPTS=(--connect-timeout 10 --max-time 180)

log() { printf '[RunnerPool] %s\n' "$*"; }
warn() { printf '[RunnerPool][WARN] %s\n' "$*" >&2; }
die() { printf '[RunnerPool][ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Paste-a-key setup — no local checkout, no flags needed:
  curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_runner_pool.sh | bash
It will prompt once, silently, for a GitHub PAT (repo admin rights) and do the rest:
resolve the current runner release, mint its own registration token, register 7
general-lane + 1 gpu-lane instance, and fold an already-existing runner at
$DEFAULT_EXISTING_DIR into the general lane automatically if one is found.
Set GH_PAT=<token> beforehand to skip the prompt entirely.

Options (all optional):
  --repo-url URL           default: https://github.com/caotiensinh/3agent
  --general-count N        default: 7  (lightweight lane, safe to run in parallel)
  --gpu-count N             default: 1  (exclusive lane, see docs/WORKSPACE_RUNNER_POOL.md)
  --base-dir DIR            default: \$HOME/actions-runner-pool
  --adopt-existing[=DIR]    force-adopt an existing runner at DIR (default: $DEFAULT_EXISTING_DIR)
  --no-adopt-existing        do not touch any pre-existing runner, even if one is found
  --token TOKEN              use this registration token instead of minting one from GH_PAT
  --remove-token TOKEN       token used to deregister the adopted runner's old identity
                              (falls back to --token/minted token if omitted)
  --tarball-url URL          skip release auto-detection, use this download URL
  --tarball-sha256 SHA256    required together with --tarball-url
  --teardown                 stop, uninstall and deregister every instance in --base-dir
  --self-test                validate arguments only, no network/system changes

The fully manual, nothing-auto-fetched path (for anyone who wants to audit every value
before it runs) is still available: pass --token, --tarball-url and --tarball-sha256,
all copied from this repo's GitHub Settings -> Actions -> Runners -> New self-hosted
runner page. In that mode GH_PAT is never read.
EOF
}

is_nonneg_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    --teardown) ACTION="teardown" ;;
    --token=*) TOKEN="${arg#*=}" ;;
    --remove-token=*) REMOVE_TOKEN="${arg#*=}" ;;
    --tarball-url=*) TARBALL_URL="${arg#*=}" ;;
    --tarball-sha256=*) TARBALL_SHA256="${arg#*=}" ;;
    --repo-url=*) REPO_URL="${arg#*=}" ;;
    --base-dir=*) BASE_DIR="${arg#*=}" ;;
    --general-count=*) GENERAL_COUNT="${arg#*=}" ;;
    --gpu-count=*) GPU_COUNT="${arg#*=}" ;;
    --adopt-existing) ADOPT_EXISTING_DIR="$DEFAULT_EXISTING_DIR"; ADOPT_EXISTING_SET=1 ;;
    --adopt-existing=*) ADOPT_EXISTING_DIR="${arg#*=}"; ADOPT_EXISTING_SET=1 ;;
    --no-adopt-existing) ADOPT_EXISTING_DIR=""; ADOPT_EXISTING_SET=1 ;;
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
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

if [[ "$ACTION" == "setup" && "$ADOPT_EXISTING_SET" == "0" && -f "$DEFAULT_EXISTING_DIR/.runner" ]]; then
  log "Found an already-registered runner at $DEFAULT_EXISTING_DIR; folding it into the" \
    "general lane automatically (pass --no-adopt-existing to leave it untouched)."
  ADOPT_EXISTING_DIR="$DEFAULT_EXISTING_DIR"
fi

owner_repo() {
  local path="${REPO_URL#https://github.com/}"
  path="${path%.git}"
  printf '%s\n' "$path"
}

ensure_pat() {
  local purpose="$1"
  [[ -n "$GH_PAT" ]] && return 0
  # Read from the controlling terminal, not fd 0: when this script is run as
  # `curl ... | bash`, fd 0 is the pipe carrying the script text itself, not a
  # terminal, so a plain `read` would silently see EOF instead of prompting.
  # Probe by actually opening /dev/tty on a spare fd rather than trusting `-r`,
  # which can report a device node readable even with no controlling terminal
  # attached (e.g. inside some sandboxes), where the open itself then fails.
  if exec 3<>/dev/tty 2>/dev/null; then
    log "Waiting for your GitHub PAT below. Paste ONLY the token (nothing else queued up in the" \
      "same paste/enter), then press Enter."
    read -rsp "GitHub PAT (repo admin, used once to mint a ${purpose} token, never stored): " GH_PAT <&3
    exec 3<&-
    echo >&2
  fi
  [[ -n "$GH_PAT" ]] || die "No PAT available (set GH_PAT, or pass --token/--remove-token/--tarball-url explicitly)"
}

mint_token() {
  local purpose="$1" # "registration" or "remove"
  ensure_pat "$purpose"
  local resp
  resp="$(curl -fsS "${CURL_API_OPTS[@]}" -X POST \
    -H "Authorization: Bearer ${GH_PAT}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$(owner_repo)/actions/runners/${purpose}-token")" \
    || die "Failed to mint a ${purpose} token via the GitHub API (check GH_PAT scope/expiry, or network/DNS reachability of api.github.com)"
  jq -r '.token' <<<"$resp"
}

resolve_release() {
  [[ -n "$TARBALL_URL" ]] && return 0
  log "Resolving the current linux-x64 actions/runner release from GitHub's public API"
  local arch os_arch latest name
  os_arch="$(uname -m)"
  case "$os_arch" in
    x86_64|amd64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported architecture for the GitHub Actions runner: $os_arch" ;;
  esac
  local -a auth_header=()
  [[ -n "$GH_PAT" ]] && auth_header=(-H "Authorization: Bearer ${GH_PAT}")
  latest="$(curl -fsSL "${CURL_API_OPTS[@]}" "${auth_header[@]}" https://api.github.com/repos/actions/runner/releases/latest)" \
    || die "Failed to query the actions/runner releases API (an unauthenticated IP can hit GitHub's rate limit, or the network/DNS didn't respond within ${CURL_API_OPTS[3]}s; set GH_PAT to raise the rate limit, or pass --tarball-url/--tarball-sha256 manually)"
  local version
  version="$(jq -r '.tag_name' <<<"$latest" | sed 's/^v//')"
  [[ -n "$version" && "$version" != "null" ]] || die "Could not resolve the latest runner version"
  name="actions-runner-linux-${arch}-${version}.tar.gz"
  TARBALL_URL="$(jq -r --arg name "$name" '.assets[] | select(.name == $name) | .browser_download_url' <<<"$latest")"
  [[ -n "$TARBALL_URL" ]] || die "Release asset $name not found in the latest actions/runner release"
  log "Resolved runner v$version for linux-$arch: $TARBALL_URL"
}

instance_names() {
  local i
  for ((i = 1; i <= GENERAL_COUNT; i++)); do printf 'general-%d self-hosted,general\n' "$i"; done
  for ((i = 1; i <= GPU_COUNT; i++)); do printf 'gpu-%d self-hosted,gpu\n' "$i"; done
}

if [[ "$ACTION" == "teardown" ]]; then
  [[ -d "$BASE_DIR" ]] || die "Nothing to tear down: $BASE_DIR does not exist"
  [[ -n "$TOKEN" ]] || TOKEN="$(mint_token remove)"
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

if [[ -n "$TARBALL_URL" ]]; then
  [[ -n "$TARBALL_SHA256" ]] || die "--tarball-sha256 is required together with --tarball-url"
else
  [[ -n "$TOKEN" ]] || ensure_pat "registration"
fi
resolve_release
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v sudo >/dev/null 2>&1 || die "sudo is required to install the runner systemd services"

[[ -n "$TOKEN" ]] || TOKEN="$(mint_token registration)"
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || die "Could not obtain a registration token"

mkdir -p "$BASE_DIR/.cache"
CACHE_TARBALL="$BASE_DIR/.cache/$(basename "$TARBALL_URL")"

if [[ -n "$TARBALL_SHA256" ]]; then
  if [[ -f "$CACHE_TARBALL" ]] \
      && echo "${TARBALL_SHA256}  ${CACHE_TARBALL}" | sha256sum -c - >/dev/null 2>&1; then
    log "Reusing already-downloaded, checksum-verified runner tarball: $CACHE_TARBALL"
  else
    log "Downloading runner release once for reuse across all $((GENERAL_COUNT + GPU_COUNT)) instances"
    curl -fsSL "${CURL_DOWNLOAD_OPTS[@]}" -o "$CACHE_TARBALL" "$TARBALL_URL"
    echo "${TARBALL_SHA256}  ${CACHE_TARBALL}" | sha256sum -c - \
      || die "Checksum mismatch for $CACHE_TARBALL; refusing to extract an unverified runner binary"
  fi
else
  if [[ -f "$CACHE_TARBALL" ]]; then
    log "Reusing already-downloaded runner tarball: $CACHE_TARBALL"
  else
    log "Downloading runner release once (over HTTPS from github.com) for reuse across all $((GENERAL_COUNT + GPU_COUNT)) instances"
    curl -fsSL "${CURL_DOWNLOAD_OPTS[@]}" -o "$CACHE_TARBALL" "$TARBALL_URL"
    log "Downloaded $(sha256sum "$CACHE_TARBALL" | cut -d' ' -f1)  $(basename "$CACHE_TARBALL")"
  fi
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

if [[ -n "$ADOPT_EXISTING_DIR" ]]; then
  if [[ -f "$ADOPT_EXISTING_DIR/.runner" ]]; then
    log "Adopting existing runner at $ADOPT_EXISTING_DIR into the general lane"
    [[ -n "$REMOVE_TOKEN" ]] || REMOVE_TOKEN="$TOKEN"
    if [[ -x "$ADOPT_EXISTING_DIR/svc.sh" ]]; then
      (cd "$ADOPT_EXISTING_DIR" && { sudo ./svc.sh stop || true; })
    fi
    (cd "$ADOPT_EXISTING_DIR" && ./config.sh remove --unattended --token "$REMOVE_TOKEN") \
      || warn "Could not deregister the existing runner's old identity; continuing to reconfigure it anyway"
    (
      cd "$ADOPT_EXISTING_DIR"
      ./config.sh --unattended --replace \
        --url "$REPO_URL" \
        --token "$TOKEN" \
        --name "aiserver-general-existing" \
        --labels "self-hosted,general" \
        --work "_work"
    )
    if [[ -x "$ADOPT_EXISTING_DIR/svc.sh" ]]; then
      (cd "$ADOPT_EXISTING_DIR" && { sudo ./svc.sh install || true; sudo ./svc.sh start; })
    fi
    log "Existing runner adopted as aiserver-general-existing (labels: self-hosted,general)"
  else
    warn "No existing runner found at $ADOPT_EXISTING_DIR; nothing adopted"
  fi
fi

while read -r name labels; do
  setup_instance "$name" "$labels"
done < <(instance_names)

log "FINAL PASS: $GENERAL_COUNT general + $GPU_COUNT gpu new runner instance(s) registered under $BASE_DIR"
[[ -n "$ADOPT_EXISTING_DIR" ]] && log "Plus the adopted existing runner at $ADOPT_EXISTING_DIR"
log "Verify on GitHub: repository Settings -> Actions -> Runners should list aiserver-general-* and aiserver-gpu-*"
log "Point lightweight CI at 'runs-on: [self-hosted, general]' and GPU-bound workflows at"
log "'runs-on: [self-hosted, gpu]' plus a shared 'concurrency: group: gpu-rtx5090-exclusive'."

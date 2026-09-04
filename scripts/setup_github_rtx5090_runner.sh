#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

# WorkSpace GitHub RTX5090 Runner bootstrap
# Target: Ubuntu 24.04 x86_64
# Security posture:
# - dedicated unprivileged OS user
# - verified official GitHub Actions Runner release digest
# - registration token is never written to disk/log
# - persistent systemd service
# - no Docker/DB/framework/model-server installation
# - no production WorkSpace configuration mutation

REPO_URL="${WORKSPACE_RUNNER_REPO_URL:-https://github.com/caotiensinh/3agent}"
RUNNER_USER="${WORKSPACE_RUNNER_USER:-github-runner}"
RUNNER_NAME="${WORKSPACE_RUNNER_NAME:-workspace-rtx5090-01}"
RUNNER_LABELS="${WORKSPACE_RUNNER_LABELS:-rtx5090,workspace-benchmark}"
RUNNER_DIR="${WORKSPACE_RUNNER_DIR:-/opt/actions-runner}"
RUNNER_WORK="${WORKSPACE_RUNNER_WORK:-_work}"
MODEL="${WORKSPACE_BENCHMARK_MODEL:-qwen3:30b}"
PULL_MODEL=0
DRY_RUN=0
SKIP_MODEL_CHECK=0
TOKEN="${GITHUB_RUNNER_TOKEN:-}"

say()  { printf '%s\n' "$*"; }
info() { printf '[INFO] %s\n' "$*"; }
pass() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

cleanup_secret() {
  TOKEN=""
  unset GITHUB_RUNNER_TOKEN 2>/dev/null || true
}
trap cleanup_secret EXIT HUP INT TERM

usage() {
  cat <<'EOF'
Usage:
  sudo bash setup_github_rtx5090_runner.sh [options]

Options:
  --repo-url URL          Repository URL (default: https://github.com/caotiensinh/3agent)
  --name NAME             Runner name (default: workspace-rtx5090-01)
  --labels CSV            Extra labels (default: rtx5090,workspace-benchmark)
  --user USER             Dedicated OS user (default: github-runner)
  --runner-dir PATH       Install directory (default: /opt/actions-runner)
  --model MODEL           Ollama model to verify (default: qwen3:30b)
  --pull-model            Pull MODEL automatically if missing
  --skip-model-check      Do not require Ollama/model readiness
  --dry-run               Print planned actions without changing the host
  -h, --help              Show this help

Registration token:
  Preferred: run the script and paste the short-lived GitHub runner registration
  token at the hidden prompt. You may also set GITHUB_RUNNER_TOKEN in the
  environment, but the script never writes the token to disk.

Manual click required only if you need a registration token:
  Repository -> Settings -> Actions -> Runners -> New self-hosted runner

Examples:
  sudo bash setup_github_rtx5090_runner.sh
  sudo bash setup_github_rtx5090_runner.sh --pull-model
EOF
}

while (($#)); do
  case "$1" in
    --repo-url) REPO_URL="${2:?missing URL}"; shift 2 ;;
    --name) RUNNER_NAME="${2:?missing NAME}"; shift 2 ;;
    --labels) RUNNER_LABELS="${2:?missing CSV}"; shift 2 ;;
    --user) RUNNER_USER="${2:?missing USER}"; shift 2 ;;
    --runner-dir) RUNNER_DIR="${2:?missing PATH}"; shift 2 ;;
    --model) MODEL="${2:?missing MODEL}"; shift 2 ;;
    --pull-model) PULL_MODEL=1; shift ;;
    --skip-model-check) SKIP_MODEL_CHECK=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"
[[ "$(uname -m)" == "x86_64" ]] || die "This script supports Linux x86_64 only."
[[ "$REPO_URL" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$ ]] \
  || die "repo URL must be a canonical https://github.com/OWNER/REPO URL"
[[ "$RUNNER_NAME" =~ ^[A-Za-z0-9._-]{1,100}$ ]] || die "Invalid runner name."
[[ "$RUNNER_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Invalid runner user."
[[ "$RUNNER_LABELS" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]] || die "Invalid runner labels."

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Expected Ubuntu; detected ${ID:-unknown}."
  if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    warn "Designed for Ubuntu 24.04; detected VERSION_ID=${VERSION_ID:-unknown}."
  fi
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}
for c in curl python3 tar sha256sum getent id systemctl runuser; do need_cmd "$c"; done

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

info "Repository : $REPO_URL"
info "Runner     : $RUNNER_NAME"
info "Labels     : $RUNNER_LABELS"
info "OS user    : $RUNNER_USER"
info "Directory  : $RUNNER_DIR"
info "Model      : $MODEL"

# ---------- Hardware gate ----------
need_cmd nvidia-smi
mapfile -t GPU_NAMES < <(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
((${#GPU_NAMES[@]} > 0)) || die "nvidia-smi returned no GPUs."

RTX5090_COUNT=0
for gpu in "${GPU_NAMES[@]}"; do
  info "GPU detected: $gpu"
  if [[ "$gpu" == *"RTX 5090"* ]]; then
    ((RTX5090_COUNT+=1))
  fi
done
((RTX5090_COUNT > 0)) || die "No RTX 5090 detected; refusing to add the rtx5090 runner label."
pass "RTX 5090 hardware gate (${RTX5090_COUNT} detected)."

# ---------- Ollama/model gate ----------
if [[ "$SKIP_MODEL_CHECK" == "0" ]]; then
  need_cmd ollama
  need_cmd curl
  curl -fsS --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null \
    || die "Ollama API is not reachable at http://127.0.0.1:11434."

  model_present() {
    python3 - "$MODEL" <<'PY'
import json, sys, urllib.request
wanted = sys.argv[1]
with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as r:
    payload = json.load(r)
names = {str(x.get("name","")) for x in payload.get("models", []) if isinstance(x, dict)}
sys.exit(0 if wanted in names else 1)
PY
  }

  if ! model_present; then
    if [[ "$PULL_MODEL" == "1" ]]; then
      info "Model $MODEL is missing; pulling once via Ollama..."
      run ollama pull "$MODEL"
      [[ "$DRY_RUN" == "1" ]] || model_present || die "Model pull completed but $MODEL is still not listed."
    else
      die "Required benchmark model '$MODEL' is missing. Re-run with --pull-model or choose --model MODEL."
    fi
  fi
  pass "Ollama + benchmark model gate."
else
  warn "Ollama/model readiness check skipped by operator."
fi

# ---------- Dedicated identity ----------
if ! getent passwd "$RUNNER_USER" >/dev/null; then
  info "Creating dedicated unprivileged user: $RUNNER_USER"
  run useradd --create-home --shell /bin/bash "$RUNNER_USER"
else
  pass "Runner user already exists."
fi

for group in video render; do
  if getent group "$group" >/dev/null; then
    run usermod -aG "$group" "$RUNNER_USER"
  fi
done

run install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0750 "$RUNNER_DIR"

# ---------- Existing configured runner: idempotent fast path ----------
RUNNER_ALREADY_CONFIGURED=0
if [[ -f "$RUNNER_DIR/.runner" && -x "$RUNNER_DIR/run.sh" ]]; then
  runner_identity="$(
    python3 - "$RUNNER_DIR/.runner" <<'PY'
import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
print(str(p.get("agentName", "")))
print(str(p.get("gitHubUrl", "")))
PY
  )" || die "Existing .runner metadata is unreadable."
  existing_name="$(printf '%s\n' "$runner_identity" | sed -n '1p')"
  existing_repo="$(printf '%s\n' "$runner_identity" | sed -n '2p')"
  [[ "$existing_name" == "$RUNNER_NAME" ]] \
    || die "Runner directory is already registered as '$existing_name', expected '$RUNNER_NAME'. Refusing to reconfigure it."
  if [[ -n "$existing_repo" && "${existing_repo%/}" != "${REPO_URL%/}" ]]; then
    die "Runner directory is registered to '$existing_repo', expected '$REPO_URL'. Refusing to reconfigure it."
  fi
  RUNNER_ALREADY_CONFIGURED=1
  info "Existing configured runner detected; preserving its registration."
fi

# ---------- Verified official runner download ----------
if [[ "$RUNNER_ALREADY_CONFIGURED" == "0" ]]; then
  info "Resolving latest official actions/runner Linux x64 release + GitHub-published SHA-256 digest..."
  release_json="$(mktemp)"
  archive="$(mktemp --suffix=.tar.gz)"
  trap 'rm -f "${release_json:-}" "${archive:-}"; cleanup_secret' EXIT HUP INT TERM

  curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    -H 'User-Agent: workspace-runner-bootstrap/1' \
    https://api.github.com/repos/actions/runner/releases/latest \
    -o "$release_json"

  read -r RUNNER_VERSION ASSET_URL ASSET_SHA < <(
    python3 - "$release_json" <<'PY'
import json, re, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
tag = str(p.get("tag_name",""))
m = re.fullmatch(r"v(\d+\.\d+\.\d+)", tag)
if not m:
    raise SystemExit("invalid runner release tag")
version = m.group(1)
expected = f"actions-runner-linux-x64-{version}.tar.gz"
for a in p.get("assets", []):
    if a.get("name") != expected:
        continue
    url = str(a.get("browser_download_url",""))
    digest = str(a.get("digest",""))
    if not re.fullmatch(r"https://github\.com/actions/runner/releases/download/v[^/]+/actions-runner-linux-x64-[^/]+\.tar\.gz", url):
        raise SystemExit("unexpected runner asset URL")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SystemExit("GitHub release asset has no valid SHA-256 digest")
    print(version, url, digest.removeprefix("sha256:"))
    break
else:
    raise SystemExit(f"asset not found: {expected}")
PY
  ) || die "Could not resolve a verified official GitHub Actions Runner asset."

  info "Official runner version: $RUNNER_VERSION"
  info "Downloading verified official runner asset..."
  if [[ "$DRY_RUN" == "1" ]]; then
    info "[DRY-RUN] curl $ASSET_URL"
  else
    curl -fL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 "$ASSET_URL" -o "$archive"
    printf '%s  %s\n' "$ASSET_SHA" "$archive" | sha256sum -c - >/dev/null \
      || die "GitHub Actions Runner SHA-256 verification FAILED."
    pass "Official runner SHA-256 verified."

    # Keep install directory clean before first configuration.
    find "$RUNNER_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    tar -xzf "$archive" -C "$RUNNER_DIR"
    chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"
  fi
fi

# ---------- Registration token ----------
if [[ "$RUNNER_ALREADY_CONFIGURED" == "0" && "$DRY_RUN" == "0" ]]; then
  if [[ -z "$TOKEN" ]]; then
    say
    say "Manual GitHub click (one time):"
    say "  $REPO_URL/settings/actions/runners/new"
    say "Copy only the short-lived registration token shown by GitHub."
    read -r -s -p "Paste GitHub runner registration token: " TOKEN
    printf '\n'
  fi
  [[ "$TOKEN" =~ ^[A-Za-z0-9_-]{10,}$ ]] || die "Registration token format is invalid/empty."

  info "Registering runner (token will not be logged or stored by this script)..."
  runner_home="$(getent passwd "$RUNNER_USER" | cut -d: -f6)"
  runuser -u "$RUNNER_USER" -- env HOME="$runner_home" bash -c '
    set -Eeuo pipefail
    cd "$1"
    ./config.sh \
      --unattended \
      --replace \
      --url "$2" \
      --token "$3" \
      --name "$4" \
      --labels "$5" \
      --work "$6"
  ' bash "$RUNNER_DIR" "$REPO_URL" "$TOKEN" "$RUNNER_NAME" "$RUNNER_LABELS" "$RUNNER_WORK"

  cleanup_secret
  RUNNER_ALREADY_CONFIGURED=1
  pass "Runner registration completed."
fi

# ---------- Persistent service ----------
if [[ "$DRY_RUN" == "0" && "$RUNNER_ALREADY_CONFIGURED" == "1" ]]; then
  cd "$RUNNER_DIR"

  service_name=""
  if [[ -s "$RUNNER_DIR/.service" ]]; then
    service_name="$(tr -d '\r\n' < "$RUNNER_DIR/.service")"
    [[ "$service_name" =~ ^actions\.runner\..+\.service$ ]] \
      || die "Runner-local .service contains an unexpected service name."
  fi

  if [[ -z "$service_name" ]]; then
    info "Installing GitHub Runner as systemd service..."
    ./svc.sh install "$RUNNER_USER"
    [[ -s "$RUNNER_DIR/.service" ]] || die "svc.sh did not create runner-local .service metadata."
    service_name="$(tr -d '\r\n' < "$RUNNER_DIR/.service")"
  fi
  [[ "$service_name" =~ ^actions\.runner\..+\.service$ ]] \
    || die "Could not resolve this runner's systemd service."

  systemctl enable "$service_name" >/dev/null
  systemctl restart "$service_name"
  systemctl is-active --quiet "$service_name" || die "Runner service failed to become active."
  service_user="$(systemctl show -p User --value "$service_name" 2>/dev/null || true)"
  [[ -z "$service_user" || "$service_user" == "$RUNNER_USER" ]] \
    || die "Runner service uses unexpected OS user '$service_user' (expected '$RUNNER_USER')."
  pass "Runner service active: $service_name"

  # Avoid needrestart interrupting a benchmark job after package activity.
  install -d -m 0755 /etc/needrestart/conf.d
  cat > /etc/needrestart/conf.d/actions_runner_services.conf <<'EOF'
$nrconf{override_rc}{qr(^actions\.runner\..+\.service$)} = 0;
EOF
  chmod 0644 /etc/needrestart/conf.d/actions_runner_services.conf
  pass "needrestart runner-service protection installed."
fi

# ---------- Runtime checks under runner identity ----------
if [[ "$DRY_RUN" == "0" && "$RUNNER_ALREADY_CONFIGURED" == "1" ]]; then
  info "Testing GPU access as $RUNNER_USER..."
  runuser -u "$RUNNER_USER" -- nvidia-smi --query-gpu=name --format=csv,noheader >/dev/null \
    || die "$RUNNER_USER cannot access NVIDIA GPU."
  pass "Runner user GPU access."

  if [[ "$SKIP_MODEL_CHECK" == "0" ]]; then
    info "Testing local Ollama access as $RUNNER_USER..."
    runuser -u "$RUNNER_USER" -- curl -fsS --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null \
      || die "$RUNNER_USER cannot reach local Ollama API."
    pass "Runner user Ollama access."
  fi

  cd "$RUNNER_DIR"
  ./svc.sh status || true

  say
  say "============================================================"
  say " WorkSpace RTX5090 GitHub Runner: READY"
  say "============================================================"
  say "Repository : $REPO_URL"
  say "Runner     : $RUNNER_NAME"
  say "Labels     : self-hosted, Linux, X64, $RUNNER_LABELS"
  say "GPUs       : ${GPU_NAMES[*]}"
  say "Service    : systemd enabled + active"
  say
  say "Final manual check (browser only):"
  say "  $REPO_URL/settings/actions/runners"
  say "Expected status: $RUNNER_NAME = Idle"
  say
  say "After this, DO NOT run ./run.sh manually."
  say "The systemd service reconnects automatically after reboot."
fi

#!/usr/bin/env bash
set -Eeuo pipefail

REPO="${WORKSPACE_RUNNER_REPO:-caotiensinh/3agent}"
MODEL="${WORKSPACE_RUNNER_MODEL:-qwen3:30b}"
RUNNER_NAME="${WORKSPACE_RUNNER_NAME:-workspace-rtx5090-local-01}"
RUNNER_LABEL="${WORKSPACE_RUNNER_LABEL:-rtx5090}"
RUNNER_ROOT="${WORKSPACE_RUNNER_ROOT:-$HOME/actions-runner-workspace}"

fail() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

info() {
  printf '[INFO] %s\n' "$*"
}

command -v gh >/dev/null 2>&1 || fail "GitHub CLI (gh) is required and must already be authenticated."
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v tar >/dev/null 2>&1 || fail "tar is required."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required."
command -v nvidia-smi >/dev/null 2>&1 || fail "nvidia-smi is required."
command -v ollama >/dev/null 2>&1 || fail "ollama is required."

[[ "$(uname -s)" == "Linux" ]] || fail "This evidence runner must be Linux."
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) fail "This evidence runner must be x86_64." ;;
esac

# Fail closed before any GitHub runner mutation.
mapfile -t GPU_NAMES < <(nvidia-smi --query-gpu=name --format=csv,noheader | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
RTX5090_COUNT=0
for gpu in "${GPU_NAMES[@]}"; do
  if [[ "$gpu" == *"RTX 5090"* ]]; then
    RTX5090_COUNT=$((RTX5090_COUNT + 1))
  fi
done
(( RTX5090_COUNT >= 2 )) || fail "At least two RTX 5090 GPUs are required; found ${RTX5090_COUNT}."

mapfile -t MATCHING_DRIVERS < <(
  nvidia-smi --query-gpu=name,driver_version --format=csv,noheader \
    | awk -F',' '/RTX 5090/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' \
    | sort -u
)
(( ${#MATCHING_DRIVERS[@]} == 1 )) || fail "Matching RTX 5090 GPUs must use one uniform driver version."

ollama show "$MODEL" >/dev/null 2>&1 || fail "Required local model '$MODEL' is not preinstalled. No model pull will be performed."

gh auth status >/dev/null 2>&1 || fail "gh is not authenticated."
gh repo view "$REPO" --json nameWithOwner --jq .nameWithOwner >/dev/null \
  || fail "Authenticated gh account cannot access repository '$REPO'."

mkdir -p "$RUNNER_ROOT"
cd "$RUNNER_ROOT"

if [[ -f .runner ]]; then
  info "A GitHub Actions runner is already configured in $RUNNER_ROOT."
  if [[ -x ./svc.sh ]]; then
    sudo ./svc.sh status || true
  fi
  info "No reconfiguration was performed."
  exit 0
fi

RELEASE_JSON="$(gh api repos/actions/runner/releases/latest)"
TAG="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' <<<"$RELEASE_JSON")"
VERSION="${TAG#v}"
ASSET_NAME="actions-runner-linux-x64-${VERSION}.tar.gz"

readarray -t ASSET_META < <(
  python3 - "$ASSET_NAME" <<'PY' <<<"$RELEASE_JSON"
import json, sys
name = sys.argv[1]
data = json.load(sys.stdin)
for asset in data.get("assets", []):
    if asset.get("name") == name:
        print(asset.get("browser_download_url", ""))
        print(asset.get("digest", ""))
        break
else:
    raise SystemExit(2)
PY
)

ASSET_URL="${ASSET_META[0]:-}"
ASSET_DIGEST="${ASSET_META[1]:-}"
[[ -n "$ASSET_URL" ]] || fail "Unable to resolve official GitHub Actions runner asset."
[[ "$ASSET_DIGEST" =~ ^sha256:[0-9a-fA-F]{64}$ ]] \
  || fail "GitHub release asset does not expose a usable SHA-256 digest; refusing unverified download."

ARCHIVE="$RUNNER_ROOT/$ASSET_NAME"
info "Downloading official GitHub Actions runner $TAG."
curl --fail --location --proto '=https' --tlsv1.2 "$ASSET_URL" --output "$ARCHIVE"
printf '%s  %s\n' "${ASSET_DIGEST#sha256:}" "$ARCHIVE" | sha256sum --check --status \
  || fail "Runner archive SHA-256 verification failed."

tar xzf "$ARCHIVE"
rm -f "$ARCHIVE"

# Registration token is ephemeral. It is never printed or persisted by this script.
set +x
REG_TOKEN="$(gh api --method POST "repos/$REPO/actions/runners/registration-token" --jq .token)"
[[ -n "$REG_TOKEN" ]] || fail "Unable to obtain an ephemeral runner registration token."

./config.sh \
  --unattended \
  --url "https://github.com/$REPO" \
  --token "$REG_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$RUNNER_LABEL" \
  --work _work \
  --replace
unset REG_TOKEN

sudo ./svc.sh install "$(id -un)"
sudo ./svc.sh start
sudo ./svc.sh status

info "Runner registered and service started."
info "Hardware preflight: RTX5090=${RTX5090_COUNT}, driver=${MATCHING_DRIVERS[0]}, model=${MODEL}."
info "No model, driver, or application data was uploaded by this bootstrap."

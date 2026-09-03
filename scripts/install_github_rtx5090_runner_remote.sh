#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

REPO="caotiensinh/3agent"
BRANCH="main"
MODEL="${WORKSPACE_BENCHMARK_MODEL:-qwen3:30b}"
API_ROOT="https://api.github.com/repos/${REPO}"
SCRIPT_PATH="scripts/setup_github_rtx5090_runner.sh"

die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
info() { printf '[INFO] %s\n' "$*"; }

for cmd in curl python3 sudo mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done
[[ -r /dev/tty && -w /dev/tty ]] || die "Interactive terminal (/dev/tty) is required."

tmp_json="$(mktemp)"
tmp_script="$(mktemp)"
cleanup() {
  rm -f "$tmp_json" "$tmp_script"
}
trap cleanup EXIT HUP INT TERM

info "Resolving exact ${REPO}@${BRANCH} source SHA..."
curl -fsSL --proto '=https' --tlsv1.2 \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: workspace-runner-remote-bootstrap/1' \
  "${API_ROOT}/branches/${BRANCH}" \
  -o "$tmp_json"

source_sha="$(python3 - "$tmp_json" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding='utf-8') as fh:
    payload = json.load(fh)
sha = str(payload.get('commit', {}).get('sha', '')).lower()
if not re.fullmatch(r'[0-9a-f]{40}', sha):
    raise SystemExit('invalid main commit SHA')
print(sha)
PY
)" || die "Could not resolve an exact main commit SHA."
info "Pinned source SHA: $source_sha"

curl -fsSL --proto '=https' --tlsv1.2 \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: workspace-runner-remote-bootstrap/1' \
  "${API_ROOT}/contents/${SCRIPT_PATH}?ref=${source_sha}" \
  -o "$tmp_json"

python3 - "$tmp_json" "$tmp_script" <<'PY'
import base64, hashlib, json, os, re, sys
metadata_path, destination = sys.argv[1:]
with open(metadata_path, encoding='utf-8') as fh:
    payload = json.load(fh)
if payload.get('type') != 'file':
    raise SystemExit('runner bootstrap path is not a file')
blob_sha = str(payload.get('sha', '')).lower()
if not re.fullmatch(r'[0-9a-f]{40}', blob_sha):
    raise SystemExit('invalid Git blob SHA')
encoded = ''.join(str(payload.get('content', '')).split())
raw = base64.b64decode(encoded, validate=True)
calculated = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
if calculated != blob_sha:
    raise SystemExit('Git blob verification failed')
if not raw.startswith(b'#!/usr/bin/env bash\n'):
    raise SystemExit('unexpected runner bootstrap content')
with open(destination, 'wb') as fh:
    fh.write(raw)
os.chmod(destination, 0o600)
print(f'[PASS] Verified setup script Git blob: {blob_sha}')
PY

info "Starting unattended host setup. Paste the short-lived GitHub runner registration token when prompted."
sudo bash "$tmp_script" --model "$MODEL" --pull-model </dev/tty

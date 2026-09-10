#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DEFAULT="$HOME/3agent"
ROOT="${THREE_AGENT_ROOT:-$ROOT_DEFAULT}"
MODEL="${THREE_AGENT_MODEL:-qwen3:30b}"
TITLE="${THREE_AGENT_E2E_TITLE:-RTX 5090 Ollama Technical Research}"
REQUEST="${THREE_AGENT_E2E_REQUEST:-Research current Ollama support for NVIDIA RTX 5090. Prefer official and primary technical sources. Remove duplicate and irrelevant information, verify factual claims against collected evidence, identify conflicting information, preserve source lineage, and prepare a clean Japanese R&D presentation.}"
AUDIENCE="${THREE_AGENT_E2E_AUDIENCE:-R&D internal}"
PURPOSE="${THREE_AGENT_E2E_PURPOSE:-inform}"
LANGUAGE="${THREE_AGENT_E2E_LANGUAGE:-ja}"
SLIDES="${THREE_AGENT_E2E_SLIDES:-6}"
FORMAT="${THREE_AGENT_E2E_FORMAT:-pptx}"
SKIP_UPDATE="${THREE_AGENT_E2E_SKIP_UPDATE:-0}"
REQUIRED_GPU_COUNT="${THREE_AGENT_REQUIRED_GPU_COUNT:-${THREE_AGENT_REQUIRED_RTX5090_COUNT:-2}}"
REQUIRED_GPU_NAME_FILTER="${THREE_AGENT_REQUIRED_GPU_NAME_FILTER-RTX 5090}"

log() { printf '[3Agent-E2E] %s\n' "$*"; }
fail() { printf '[3Agent-E2E][FAIL] %s\n' "$*" >&2; exit 1; }

self_test() {
  command -v bash >/dev/null
  [[ "$REQUIRED_GPU_COUNT" =~ ^[0-9]+$ ]]
  [[ "$SLIDES" =~ ^[0-9]+$ ]]
  case "$FORMAT" in source|pptx|pdf|all) ;; *) return 1 ;; esac
  case "$LANGUAGE" in ja|en|vi) ;; *) return 1 ;; esac
  printf 'e2e acceptance self-test PASS\n'
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

command -v git >/dev/null || fail "git is required"
command -v jq >/dev/null || fail "jq is required"
command -v curl >/dev/null || fail "curl is required"
command -v nvidia-smi >/dev/null || fail "nvidia-smi is required"
command -v ollama >/dev/null || fail "ollama is required"
command -v python3 >/dev/null || fail "python3 is required"

[[ -d "$ROOT/.git" ]] || fail "3Agent checkout not found: $ROOT"
cd "$ROOT"

log "Checking NVIDIA runtime. Driver/kernel mutation is not permitted by this script."
if ! nvidia-smi >/dev/null 2>&1; then
  fail "nvidia-smi is unhealthy"
fi

mapfile -t GPU_NAMES < <(nvidia-smi --query-gpu=name --format=csv,noheader)
RTX5090_COUNT="$(printf '%s\n' "${GPU_NAMES[@]}" | grep -F -c 'RTX 5090' || true)"
if [[ -n "$REQUIRED_GPU_NAME_FILTER" ]]; then
  GPU_COUNT="$(printf '%s\n' "${GPU_NAMES[@]}" | grep -F -c "$REQUIRED_GPU_NAME_FILTER" || true)"
  GPU_REQUIREMENT="$REQUIRED_GPU_NAME_FILTER"
else
  GPU_COUNT="${#GPU_NAMES[@]}"
  GPU_REQUIREMENT="NVIDIA GPU"
fi
if (( GPU_COUNT < REQUIRED_GPU_COUNT )); then
  fail "Expected at least $REQUIRED_GPU_COUNT $GPU_REQUIREMENT devices, found $GPU_COUNT"
fi
log "GPU PASS: $GPU_COUNT matching $GPU_REQUIREMENT devices detected"
nvidia-smi --query-gpu=index,name,driver_version,memory.total,uuid --format=csv,noheader

log "Checking Ollama API and configured model"
if ! curl -fsS --connect-timeout 5 --max-time 15 http://127.0.0.1:11434/api/tags >/dev/null; then
  fail "Ollama API is not reachable at 127.0.0.1:11434"
fi
if ! ollama list | awk 'NR>1 {print $1}' | grep -Fxq "$MODEL"; then
  fail "Required model is not installed: $MODEL"
fi
log "Ollama PASS: model $MODEL is available"

if [[ "$SKIP_UPDATE" != "1" ]]; then
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    fail "Tracked repository files are dirty; refusing automatic update"
  fi
  log "Fast-forwarding repository to origin/main"
  git fetch origin main
  git checkout main >/dev/null 2>&1
  git merge --ff-only origin/main
fi

[[ -x "$ROOT/.venv/bin/python" ]] || fail "Python venv is missing: $ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install -e . >/dev/null

SOURCE_CONFIG="${THREE_AGENT_CONFIG:-config/local.json}"
[[ -f "$SOURCE_CONFIG" ]] || fail "Config file not found: $SOURCE_CONFIG"
E2E_RUNTIME_ROOT="${THREE_AGENT_E2E_RUNTIME_DIR:-${RUNNER_TEMP:-$ROOT/data/acceptance-runtime}/workspace-e2e-${LANGUAGE}-$$}"
rm -rf "$E2E_RUNTIME_ROOT"
install -d -m 700 "$E2E_RUNTIME_ROOT" "$ROOT/data" "$ROOT/data/activity"
E2E_CONFIG="$E2E_RUNTIME_ROOT/config.json"
"$ROOT/.venv/bin/python" - "$SOURCE_CONFIG" "$E2E_CONFIG" "$E2E_RUNTIME_ROOT" "$ROOT/data" <<'PY'
import json
import pathlib
import sys

source, target, runtime_root, artifact_root = map(pathlib.Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
runtime_root.mkdir(parents=True, exist_ok=True)
artifact_root.mkdir(parents=True, exist_ok=True)

data["database_path"] = str(runtime_root / "tasks.db")
data["artifact_root"] = str(artifact_root)

# This script is the isolated physical E2E acceptance boundary. Its prompts are
# intentionally public technical research, so bind the task to the existing
# public-research authority instead of inheriting a production confidential
# config that correctly omits web_gateway from the immutable TaskContract.
# The source config is never modified. The temporary copy remains strict,
# fail-closed, and limited to the reviewed search-provider allowlist below.
data["environment"] = "public-research-zone"
data["confidentiality_mode"] = "public-research"

internet = data.get("internet_gateway")
if not isinstance(internet, dict):
    raise SystemExit("E2E acceptance requires internet_gateway configuration")

approved_search_hosts = {
    "html.duckduckgo.com",
    "lite.duckduckgo.com",
    "www.bing.com",
}
configured_hosts = internet.get("allowed_search_hosts")
if not isinstance(configured_hosts, list):
    raise SystemExit("E2E acceptance requires an explicit allowed_search_hosts list")
scoped_hosts = [
    str(host).strip().casefold()
    for host in configured_hosts
    if str(host).strip().casefold() in approved_search_hosts
]
if not scoped_hosts:
    raise SystemExit("E2E acceptance has no approved search provider in allowed_search_hosts")

internet["enabled"] = True
internet["mode"] = "strict"
internet["public_search_enabled"] = True
internet["allow_all_outbound_in_test"] = False
internet["allowed_search_hosts"] = sorted(set(scoped_hosts))
# E2E exercises the application InternetGateway itself. Direct mode here does
# not grant arbitrary network access: strict search/fetch methods, DLP, exact
# task capability authority, HTTPS validation, host allowlists and one-time
# result-derived fetch grants remain enforced. Production config is unchanged.
internet["direct_egress"] = True
internet["audit_log"] = str(runtime_root / "internet-egress.jsonl")

execution = data.get("execution_gateway")
if isinstance(execution, dict):
    execution["audit_log"] = str(runtime_root / "execution.jsonl")

target.write_text(
    json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY
chmod 600 "$E2E_CONFIG"
export THREE_AGENT_CONFIG="$E2E_CONFIG"
export LOCAL_LLM_MODEL="${LOCAL_LLM_MODEL:-$MODEL}"
log "Prepared isolated writable acceptance config; production config remains unchanged."

log "Running harness smoke"
"$ROOT/.venv/bin/three-agent" smoke | jq -e '
  .llm_provider == "ollama" and
  .llm_model_configured == true and
  .research_web_enabled == true and
  .runtime_validator_public_web == true
' >/dev/null

STAMP="$(date +%Y%m%d-%H%M%S)"
EVIDENCE_DIR="$ROOT/data/acceptance/$STAMP"
mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"
RESULT_JSON="$EVIDENCE_DIR/workflow-result.json"
STDERR_LOG="$EVIDENCE_DIR/workflow-stderr.log"
SYSTEM_JSON="$EVIDENCE_DIR/system.json"

jq -n \
  --arg timestamp "$(date --iso-8601=seconds)" \
  --arg head "$(git rev-parse HEAD)" \
  --arg model "$MODEL" \
  --arg driver "$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1)" \
  --arg gpu_name_filter "$REQUIRED_GPU_NAME_FILTER" \
  --argjson gpu_match_count "$GPU_COUNT" \
  --argjson rtx5090_count "$RTX5090_COUNT" \
  '{timestamp:$timestamp,git_head:$head,model:$model,nvidia_driver:$driver,gpu_name_filter:$gpu_name_filter,gpu_match_count:$gpu_match_count,rtx5090_count:$rtx5090_count}' \
  > "$SYSTEM_JSON"

log "Running live Research -> Presentation -> Daily Report workflow"
set +e
"$ROOT/.venv/bin/three-agent" workflow-run \
  --title "$TITLE" \
  --request "$REQUEST" \
  --live \
  --audience "$AUDIENCE" \
  --purpose "$PURPOSE" \
  --language "$LANGUAGE" \
  --slides "$SLIDES" \
  --format "$FORMAT" \
  >"$RESULT_JSON" 2>"$STDERR_LOG"
RC=$?
set -e

if ! jq -e . "$RESULT_JSON" >/dev/null 2>&1; then
  fail "Workflow did not return valid JSON. See $STDERR_LOG"
fi

STATUS="$(jq -r '.status' "$RESULT_JSON")"
TASK_STATUS="$(jq -r '.task_status' "$RESULT_JSON")"
TASK_ID="$(jq -r '.task_id' "$RESULT_JSON")"
MANIFEST="$(jq -r '.manifest_path' "$RESULT_JSON")"

collect_blocked_research_evidence() {
  local research_json handoff
  research_json="$(find "$ROOT/data/research" -type f -name "${TASK_ID}.json" -print | sort | tail -n1)"
  handoff="$(find "$ROOT/data/research" -type f -name "${TASK_ID}_handoff.json" -print | sort | tail -n1)"

  if [[ -f "$research_json" ]]; then
    cp "$research_json" "$EVIDENCE_DIR/research.json"
    log "Research diagnostics:"
    jq '{status, search_queries, search_errors, sources: [.sources[]? | {source_id,title,url,fetch_status,error}]}' "$research_json" || true
  fi
  if [[ -f "$handoff" ]]; then
    cp "$handoff" "$EVIDENCE_DIR/research-handoff.json"
    log "Research gate:"
    jq '{presentation_ready, blockers, quality_metrics}' "$handoff" || true
  fi
  if [[ -f "$MANIFEST" ]]; then
    cp "$MANIFEST" "$EVIDENCE_DIR/workflow-manifest.json"
  fi
}

if [[ "$RC" -eq 2 || "$STATUS" == "blocked" ]]; then
  log "BLOCKED: Agent 1 quality gate did not authorize downstream presentation."
  collect_blocked_research_evidence
  jq . "$RESULT_JSON"
  printf '[3Agent-E2E][BLOCKED] Evidence: %s\n' "$EVIDENCE_DIR" >&2
  exit 2
fi
if [[ "$RC" -ne 0 ]]; then
  jq . "$RESULT_JSON" || true
  fail "Workflow failed with exit code $RC. Evidence: $EVIDENCE_DIR"
fi

[[ "$STATUS" == "completed" ]] || fail "Expected workflow status completed, got $STATUS"
[[ "$TASK_STATUS" == "DONE" ]] || fail "Expected task status DONE, got $TASK_STATUS"
[[ -n "$TASK_ID" && "$TASK_ID" != "null" ]] || fail "Missing task_id"
[[ -f "$MANIFEST" ]] || fail "Workflow manifest not found: $MANIFEST"

jq -e '
  .schema_version == "workflow-run/v1" and
  .status == "completed" and
  .task_status == "DONE" and
  (.artifacts.research | length > 0) and
  (.artifacts.presentation | length > 0) and
  (.artifacts.daily_report | length > 0) and
  (.error == null)
' "$MANIFEST" >/dev/null || fail "Workflow manifest acceptance contract failed"

HANDOFF="$(find "$ROOT/data/research" -type f -name "${TASK_ID}_handoff.json" -print | sort | tail -n1)"
[[ -f "$HANDOFF" ]] || fail "Research handoff not found for $TASK_ID"
jq -e '.presentation_ready == true and (.key_facts | length > 0) and (.blockers | length == 0)' "$HANDOFF" >/dev/null \
  || fail "Research handoff is not presentation-ready"

PRESENTATION_JSON="$(find "$ROOT/data/presentations" -type f -name "${TASK_ID}.json" -print | sort | tail -n1)"
[[ -f "$PRESENTATION_JSON" ]] || fail "Presentation JSON not found for $TASK_ID"
jq -e '.task_id == $tid and (.qa.errors | length == 0)' --arg tid "$TASK_ID" "$PRESENTATION_JSON" >/dev/null \
  || fail "Presentation QA contract failed"

if [[ "$FORMAT" != "source" ]]; then
  case "$FORMAT" in
    pptx) jq -e '.generated_artifacts.pptx | strings | length > 0' "$PRESENTATION_JSON" >/dev/null ;;
    pdf) jq -e '.generated_artifacts.pptx and .generated_artifacts.pdf' "$PRESENTATION_JSON" >/dev/null ;;
    all) jq -e '.generated_artifacts.pptx and .generated_artifacts.pdf' "$PRESENTATION_JSON" >/dev/null ;;
  esac || fail "Requested presentation file was not generated"
  while IFS= read -r artifact; do
    [[ -f "$artifact" ]] || fail "Generated presentation artifact missing: $artifact"
  done < <(jq -r '.generated_artifacts[]' "$PRESENTATION_JSON")
fi

REPORT_DATE="$(jq -r '.report_date' "$MANIFEST")"
DAILY_JSON="$ROOT/data/daily_reports/${REPORT_DATE}.json"
[[ -f "$DAILY_JSON" ]] || fail "Daily report JSON not found: $DAILY_JSON"
jq -e --arg tid "$TASK_ID" '
  (.evidence.tasks | any(.task_id == $tid)) and
  (.source_counts.tasks > 0) and
  (.evidence_digest | startswith("sha256:"))
' "$DAILY_JSON" >/dev/null || fail "Daily report does not contain task evidence"

cp "$MANIFEST" "$EVIDENCE_DIR/workflow-manifest.json"
cp "$HANDOFF" "$EVIDENCE_DIR/research-handoff.json"
cp "$PRESENTATION_JSON" "$EVIDENCE_DIR/presentation.json"
cp "$DAILY_JSON" "$EVIDENCE_DIR/daily-report.json"

log "FINAL PASS: 3Agent live E2E workflow completed."
printf 'Task: %s\n' "$TASK_ID"
printf 'HEAD: %s\n' "$(git rev-parse HEAD)"
printf 'Evidence: %s\n' "$EVIDENCE_DIR"
printf 'Manifest: %s\n' "$MANIFEST"
printf '\nGPU state:\n'
nvidia-smi
printf '\nOllama state:\n'
ollama ps || true

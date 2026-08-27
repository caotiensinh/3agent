#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/run_e2e_acceptance.sh
bash scripts/run_e2e_acceptance.sh --self-test

grep -Fq 'workflow-run' scripts/run_e2e_acceptance.sh
grep -Fq 'presentation_ready == true' scripts/run_e2e_acceptance.sh
grep -Fq 'workflow-run/v1' scripts/run_e2e_acceptance.sh
grep -Fq 'FINAL PASS: 3Agent live E2E workflow completed.' scripts/run_e2e_acceptance.sh
grep -Fq 'RTX 5090' scripts/run_e2e_acceptance.sh
grep -Fq 'Driver/kernel mutation is not permitted' scripts/run_e2e_acceptance.sh

echo "e2e acceptance contract PASS"

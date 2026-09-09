#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UBUNTU_ENTRYPOINT="$ROOT/install.sh"
WINDOWS_ENTRYPOINT="$ROOT/install.ps1"

fail() {
  printf '[one-command-contract][FAIL] %s\n' "$*" >&2
  exit 1
}

[[ -f "$UBUNTU_ENTRYPOINT" ]] || fail "Missing install.sh"
[[ -f "$WINDOWS_ENTRYPOINT" ]] || fail "Missing install.ps1"

bash -n "$UBUNTU_ENTRYPOINT"
SELF_TEST_OUTPUT="$(bash "$UBUNTU_ENTRYPOINT" --self-test)"
printf '%s\n' "$SELF_TEST_OUTPUT" | grep -Fq 'One-command Ubuntu entrypoint self-test PASS' \
  || fail "Ubuntu entrypoint self-test marker missing"

for marker in \
  'caotiensinh/3agent' \
  'WORKSPACE_SOURCE_REF' \
  'THREE_AGENT_REPO_REF' \
  '/scripts/deploy_ubuntu_pc.sh' \
  '/scripts/bootstrap.sh'; do
  grep -Fq "$marker" "$UBUNTU_ENTRYPOINT" || fail "Ubuntu entrypoint missing marker: $marker"
done

for marker in \
  'caotiensinh/3agent' \
  'WORKSPACE_SOURCE_REF' \
  'THREE_AGENT_REPO_REF' \
  '/scripts/bootstrap.ps1' \
  'WORKSPACE_INSTALLER_SHA256'; do
  grep -Fq "$marker" "$WINDOWS_ENTRYPOINT" || fail "Windows entrypoint missing marker: $marker"
done

# Root entrypoints are trust/bootstrap shims only. Installation logic must remain
# in the canonical platform scripts so fixes do not diverge across copies.
for forbidden in \
  'git clone' \
  'pip install' \
  'python3 -m venv' \
  'apt-get install' \
  'dnf install' \
  'yum install'; do
  if grep -Fq "$forbidden" "$UBUNTU_ENTRYPOINT"; then
    fail "Ubuntu root entrypoint duplicated installer logic: $forbidden"
  fi
done

for forbidden in \
  'git clone' \
  'pip install' \
  'python -m venv' \
  'winget install'; do
  if grep -Fqi "$forbidden" "$WINDOWS_ENTRYPOINT"; then
    fail "Windows root entrypoint duplicated installer logic: $forbidden"
  fi
done

printf '[one-command-contract] PASS\n'

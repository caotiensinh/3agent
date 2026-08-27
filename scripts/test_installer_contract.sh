#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install_ubuntu_2404_rtx5090.sh
bash -n scripts/verify_deployment.sh
bash scripts/install_ubuntu_2404_rtx5090.sh --self-test

grep -Fq 'Ubuntu 24.04.4' scripts/install_ubuntu_2404_rtx5090.sh
grep -Fq 'RTX 5090' scripts/install_ubuntu_2404_rtx5090.sh
grep -Fq 'CUDA_VISIBLE_DEVICES' scripts/install_ubuntu_2404_rtx5090.sh
grep -Fq 'resume-required' scripts/install_ubuntu_2404_rtx5090.sh
grep -Fq 'config/local.json' scripts/install_ubuntu_2404_rtx5090.sh

echo "installer contract PASS"

#!/usr/bin/env bash
set -u
ip -br link
ip -br addr
ip route
ip neigh
if command -v resolvectl >/dev/null 2>&1; then resolvectl status; fi
ss -s

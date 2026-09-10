#!/usr/bin/env bash
set -u
journalctl -b -1 -p warning..alert --no-pager
printf '\n===== previous boot kernel =====\n'
journalctl -k -b -1 --no-pager

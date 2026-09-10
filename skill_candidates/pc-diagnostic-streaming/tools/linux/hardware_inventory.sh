#!/usr/bin/env bash
set -u
uname -a
printf '\n===== PCI =====\n'
lspci -nnk
printf '\n===== USB =====\n'
lsusb
printf '\n===== block devices =====\n'
lsblk -o NAME,MODEL,SERIAL,SIZE,TYPE,FSTYPE,MOUNTPOINTS
printf '\n===== memory =====\n'
free -h

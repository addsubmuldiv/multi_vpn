#!/bin/sh
cd "$(dirname "$0")" || exit 1
exec sudo env MULTIVPN_DATA_DIR="$PWD/local-user" "$PWD/.venv/bin/python" -m multi_vpn

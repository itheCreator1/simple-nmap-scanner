#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${SCRIPT_DIR}/.venv"

# Check if virtual environment exists
if [[ ! -f "${VENV_PATH}/bin/activate" ]]; then
    echo "ERROR: Virtual environment not found at ${VENV_PATH}" >&2
    echo "Run: ./setup.sh" >&2
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "ERROR: nmap is not installed" >&2
    echo "Run: ./setup.sh (it will show install instructions)" >&2
    exit 1
fi

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <target_ip> <port>" >&2
  echo "Example: $0 192.168.1.100 22" >&2
  exit 1
fi

target_ip="$1"
port="$2"
parser="${SCRIPT_DIR}/single_port_service_scan_parser.py"

# Activate Python virtual environment
source "${VENV_PATH}/bin/activate"

xml_output=$(nmap -sV -Pn -T4 \
  --host-timeout 5s \
  --max-rtt-timeout 300ms \
  --max-retries 0 \
  --version-intensity 0 \
  "$target_ip" -p "$port" -oX - 2>/dev/null)

# Check if XML has actual port data
if echo "$xml_output" | grep -q "<ports>"; then
  echo "$xml_output" | python3 "$parser"
else
  echo "$target_ip $port tcp open timeout Service detection timeout"
fi

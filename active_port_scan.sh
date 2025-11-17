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

# Activate Python virtual environment
source "${VENV_PATH}/bin/activate"

# Use the first argument as the scan target, default to 'localhost' if not provided
target="${1:-localhost}"

# Path to the Python parser script
parser="${SCRIPT_DIR}/active_port_parser.py"

# Run Nmap scan on top 1000 ports and parse output with Python script
nmap --top-ports 1000 -Pn -T4 \
  --host-timeout 30s \
  --max-rtt-timeout 2s \
  --max-scan-delay 1s \
  "$target" -oX - | python3 "$parser"

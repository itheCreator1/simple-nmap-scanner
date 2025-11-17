#!/usr/bin/env bash
set -euo pipefail

# Description:
# Scans a given or detected local network for active hosts using Nmap
# and parses the XML output using a Python script.

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

# Use first argument as CIDR if given, otherwise auto-detect
cidr="${1:-$(ip -o -f inet addr show scope global | awk '{print $4}' | head -n1)}"

# Path to the Python parser script
parser="${SCRIPT_DIR}/active_host_parser.py"

# Run nmap ping scan and parse the output
nmap -sn -T4 "$cidr" -oX - | python3 "$parser"

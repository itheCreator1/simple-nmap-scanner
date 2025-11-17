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

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <target_ip> <port> <service_name>" >&2
    echo "Example: $0 192.168.1.100 80 http" >&2
    exit 1
fi

target_ip="$1"
port="$2"
service_name="$3"

# Activate Python virtual environment
source "${VENV_PATH}/bin/activate"

scripts_json=$(python3 "${SCRIPT_DIR}/nse_selector.py" --service "$service_name" --port "$port" --json 2>/dev/null)

script_names=$(echo "$scripts_json" | python3 -c "import sys, json; data = json.load(sys.stdin); print(','.join([s['script'] for s in data[:3]]))" 2>/dev/null)

if [[ -z "$script_names" ]]; then
    # Output minimal valid XML so parser doesn't complain
    echo '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
    exit 0
fi

nmap -sV -Pn -T4 --script "$script_names" -p "$port" "$target_ip" -oX - 2>/dev/null

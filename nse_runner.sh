#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <target_ip> <port> <service_name>"
    echo "Example: $0 192.168.1.100 80 http"
    exit 1
fi

target_ip="$1"
port="$2"
service_name="$3"

source .venv/bin/activate

scripts_json=$(python3 nse_selector.py --service "$service_name" --port "$port" --json 2>/dev/null)

script_names=$(echo "$scripts_json" | python3 -c "import sys, json; data = json.load(sys.stdin); print(','.join([s['script'] for s in data[:3]]))" 2>/dev/null)

if [[ -z "$script_names" ]]; then
    # Output minimal valid XML so parser doesn't complain
    echo '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
    exit 0
fi

nmap -sV -Pn -T4 --script "$script_names" -p "$port" "$target_ip" -oX - 2>/dev/null
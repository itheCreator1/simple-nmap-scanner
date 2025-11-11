#!/usr/bin/env bash

# Use the first argument as the scan target, default to 'localhost' if not provided
target="${1:-localhost}"

# Path to the Python parser script
parser="./active_port_parser.py"

# Activate Python virtual environment
source .venv/bin/activate

# Run Nmap scan on top 5000 ports and parse output with Python script
nmap --top-ports 1000 -Pn -T4 \
  --host-timeout 30s \
  --max-rtt-timeout 2s \
  --max-scan-delay 1s \
  "$target" -oX - | python3 "$parser"


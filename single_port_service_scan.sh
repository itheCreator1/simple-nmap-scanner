#!/usr/bin/env bash

# Description:
# Scans a single target IP and port using Nmap and parses the output with a Python script.

# Check if exactly two arguments are provided
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <target_ip> <port>"
  echo "Example: $0 192.168.1.100 22"
  exit 1
fi

# Assign arguments
target_ip="$1"
port="$2"

# Path to the Python parser script
parser="./single_port_service_scan_parser.py"

# Activate Python virtual environment
source .venv/bin/activate

# Run Nmap with service/version detection and timeouts
nmap -sV -Pn -T4 \
  --host-timeout 30s \
  --max-rtt-timeout 2s \
  --version-intensity 5 \
  "$target_ip" -p "$port" -oX - | python3 "$parser"

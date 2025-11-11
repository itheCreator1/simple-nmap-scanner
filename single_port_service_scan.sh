#!/usr/bin/env bash

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <target_ip> <port>"
  echo "Example: $0 192.168.1.100 22"
  exit 1
fi

target_ip="$1"
port="$2"
parser="./single_port_service_scan_parser.py"

source .venv/bin/activate

xml_output=$(nmap -sV -Pn -T4 \
  --host-timeout 8s \
  --max-rtt-timeout 500ms \
  --max-retries 1 \
  --version-intensity 2 \
  "$target_ip" -p "$port" -oX - 2>/dev/null)

# Check if XML has actual port data
if echo "$xml_output" | grep -q "<ports>"; then
  echo "$xml_output" | python3 "$parser"
else
  # Timeout occurred, provide fallback
  echo "$target_ip $port tcp open timeout Service detection timeout"
fi
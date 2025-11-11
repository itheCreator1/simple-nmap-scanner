#!/usr/bin/env bash

# Description:
# Performs an Nmap scan on ports 80 and 443 using several HTTP scripts,
# and parses the XML output with a Python parser.

# Check if IP is provided
if [[ -z "$1" ]]; then
  echo "Usage: $0 <target_ip>"
  echo "Example: $0 192.168.1.100"
  exit 1
fi

# Assign the target IP
target_ip="$1"

# Path to the Python parser script
parser="./http_info_parser.py"

# Activate Python virtual environment
source /home/ahead/.local/venv/bin/activate

# Run the Nmap scan with HTTP scripts and parse the XML output
nmap -p 80,443 -sV \
  --script http-title,http-headers,http-methods,http-robots.txt,http-security-headers \
  "$target_ip" -oX - | python3 "$parser"


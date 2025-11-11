#!/usr/bin/env bash

# Description:
# Scans a given or detected local network for active hosts using Nmap
# and parses the XML output using a Python script.

# Use first argument as CIDR if given, otherwise auto-detect
cidr="${1:-$(ip -o -f inet addr show scope global | awk '{print $4}' | head -n1)}"

# Path to the Python parser script
parser="./active_host_parser.py"

# Activate Python virtual environment
source .venv/bin/activate

# Run nmap ping scan and parse the output
nmap -sn -T4 "$cidr" -oX - | python3 "$parser"


#!/usr/bin/env python3
"""
Service Version Detection Parser
===============================

Parses Nmap XML output to extract detailed service version information including
product, version, and extra info (fingerprinting).

Expected Nmap commands:
  nmap -sV -p 80,443 192.168.1.100 -oX - | python3 single_port_service_scan_parser.py
  nmap -sS -sV --version-intensity 5 target.com -oX - | python3 single_port_service_scan_parser.py
  nmap -sV --version-all -p- 192.168.1.1 -oX - | python3 single_port_service_scan_parser.py
  nmap -A -p 1-1000 target.com -oX - | python3 single_port_service_scan_parser.py

Usage:
  nmap -sV [options] [target] -oX - | python3 single_port_service_scan_parser.py
"""

import sys
import pandas as pd
from common_parser import read_and_parse_xml, safe_get_attrib

# Read and parse XML with error handling
root = read_and_parse_xml()
if root is None:
    sys.exit(1)

data = []

for host in root.findall('host'):
    ip_elem = host.find('address[@addrtype="ipv4"]')
    ip = safe_get_attrib(ip_elem, 'addr', 'N/A')

    # Check if ports element exists
    ports_elem = host.find('ports')
    if ports_elem is None:
        continue

    for port in ports_elem.findall('port'):
        portid = int(port.attrib.get('portid', 0))
        protocol = safe_get_attrib(port, 'protocol', 'tcp')

        state_elem = port.find('state')
        if state_elem is None:
            continue
        state = safe_get_attrib(state_elem, 'state', 'unknown')

        service_elem = port.find('service')
        service = safe_get_attrib(service_elem, 'name', 'unknown')
        product = safe_get_attrib(service_elem, 'product', '')
        version = safe_get_attrib(service_elem, 'version', '')
        extrainfo = safe_get_attrib(service_elem, 'extrainfo', '')

        # Compose a fingerprint string from product/version/extrainfo
        fingerprint = " ".join(filter(None, [product, version, extrainfo])) or "—"

        data.append({
            'IP': ip,
            'Port': portid,
            'Protocol': protocol,
            'State': state,
            'Service': service,
            'Fingerprint': fingerprint
        })

# Output results
print("Service Version Detection Result:\n")

if not data:
    print("No scan results found.")
else:
    df = pd.DataFrame(data)
    df = df.sort_values(by="Port")
    print(df.to_string(index=False))

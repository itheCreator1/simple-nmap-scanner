#!/usr/bin/env python3
"""
Active Port Scanner Parser
=========================

Parses Nmap XML output to extract open ports with service information.

Expected Nmap commands:
  nmap -sS -p- 192.168.1.100 -oX - | python3 active_port_parser.py
  nmap -sT -p 1-1000 target.com -oX - | python3 active_port_parser.py
  nmap -sU -p 53,67,68,123,161 192.168.1.1 -oX - | python3 active_port_parser.py
  nmap -p 22,80,443,8080 --top-ports 1000 192.168.1.0/24 -oX - | python3 active_port_parser.py

Usage:
  nmap [scan_type] -p [ports] [target] -oX - | python3 active_port_parser.py
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

    ports_elem = host.find('ports')
    if ports_elem is None:
        continue

    for port in ports_elem.findall('port'):
        portid = int(port.attrib.get('portid', 0))
        protocol = safe_get_attrib(port, 'protocol', 'tcp')

        state_elem = port.find('state')
        state = safe_get_attrib(state_elem, 'state', 'unknown')
        reason = safe_get_attrib(state_elem, 'reason', 'unknown')

        service_elem = port.find('service')
        service = safe_get_attrib(service_elem, 'name', 'unknown')

        data.append({
            'IP': ip,
            'Port': portid,
            'Protocol': protocol,
            'State': state,
            'Reason': reason,
            'Service': service
        })

# Create DataFrame and display results
print("Port Scan Results:\n")

if not data:
    print("No ports found or all ports are closed/filtered.")
else:
    df = pd.DataFrame(data)
    df = df.sort_values(by="Port")
    print(df.to_string(index=False))

#!/usr/bin/env python3
"""
Active Host Discovery Parser
===========================

Parses Nmap XML output to extract active hosts with IP, MAC, and vendor information.

Expected Nmap commands:
  nmap -sn 192.168.1.0/24 -oX - | python3 active_host_parser.py
  nmap -sn --send-ip 10.0.0.0/8 -oX - | python3 active_host_parser.py
  nmap -PE -sn 172.16.0.0/12 -oX - | python3 active_host_parser.py

Usage:
  nmap -sn [target] -oX - | python3 active_host_parser.py
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
    status = host.find('status')
    if status is None or safe_get_attrib(status, 'state') != 'up':
        continue

    ip_elem = host.find('address[@addrtype="ipv4"]')
    mac_elem = host.find('address[@addrtype="mac"]')

    data.append({
        'IP': safe_get_attrib(ip_elem, 'addr', 'N/A'),
        'MAC': safe_get_attrib(mac_elem, 'addr', 'None'),
        'Vendor': safe_get_attrib(mac_elem, 'vendor', 'None')
    })

# Create DataFrame and print
if not data:
    print("Active Hosts:\n")
    print("No active hosts found.")
else:
    df = pd.DataFrame(data)
    print("Active Hosts:\n")
    print(df.to_string(index=False))

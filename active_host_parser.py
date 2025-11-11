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
import xml.etree.ElementTree as ET

# Read XML from stdin
xml_string = sys.stdin.read()
root = ET.fromstring(xml_string)

data = []

for host in root.findall('host'):
    status = host.find('status').attrib.get('state')
    if status != 'up':
        continue

    ip_elem = host.find('address[@addrtype="ipv4"]')
    mac_elem = host.find('address[@addrtype="mac"]')

    data.append({
        'IP': ip_elem.attrib.get('addr') if ip_elem is not None else None,
        'MAC': mac_elem.attrib.get('addr') if mac_elem is not None else None,
        'Vendor': mac_elem.attrib.get('vendor') if mac_elem is not None and 'vendor' in mac_elem.attrib else None
    })

# Create DataFrame and print
df = pd.DataFrame(data)
print("Active Hosts:\n")
print(df.to_string(index=False))
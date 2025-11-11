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
import xml.etree.ElementTree as ET

# Read XML from stdin
xml_string = sys.stdin.read()
root = ET.fromstring(xml_string)

data = []

for host in root.findall('host'):
    ip_elem = host.find('address[@addrtype="ipv4"]')
    ip = ip_elem.attrib.get('addr') if ip_elem is not None else "N/A"

    ports_elem = host.find('ports')
    if ports_elem is None:
        continue
        
    for port in ports_elem.findall('port'):
        portid = int(port.attrib.get('portid'))
        protocol = port.attrib.get('protocol')
        state = port.find('state').attrib.get('state')
        reason = port.find('state').attrib.get('reason')
        
        service_elem = port.find('service')
        service = service_elem.attrib.get('name') if service_elem is not None else "unknown"

        data.append({
            'IP': ip,
            'Port': portid,
            'Protocol': protocol,
            'State': state,
            'Reason': reason,
            'Service': service
        })

# Create DataFrame and display results
df = pd.DataFrame(data)
print("Port Scan Results:\n")

if df.empty:
    print("No ports found or all ports are closed/filtered.")
else:
    df = df.sort_values(by="Port")
    print(df.to_string(index=False))

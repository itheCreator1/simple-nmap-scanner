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
import xml.etree.ElementTree as ET

xml_string = sys.stdin.read()
if not xml_string.strip():
    print("No XML input detected. Did you forget to pipe Nmap output?")
    sys.exit(1)

try:
    root = ET.fromstring(xml_string)
except ET.ParseError as e:
    print(f"Error parsing XML: {e}")
    sys.exit(1)

data = []

for host in root.findall('host'):
    ip_elem = host.find('address[@addrtype="ipv4"]')
    ip = ip_elem.attrib.get('addr') if ip_elem is not None else "N/A"

    # Check if ports element exists
    ports_elem = host.find('ports')
    if ports_elem is None:
        print(f"No ports found for host {ip}")
        continue

    for port in ports_elem.findall('port'):
        portid = int(port.attrib.get('portid'))
        protocol = port.attrib.get('protocol')
        
        state_elem = port.find('state')
        if state_elem is None:
            continue
        state = state_elem.attrib.get('state')

        service_elem = port.find('service')
        service = service_elem.attrib.get('name', 'unknown') if service_elem is not None else 'unknown'
        product = service_elem.attrib.get('product', '') if service_elem is not None else ''
        version = service_elem.attrib.get('version', '') if service_elem is not None else ''
        extrainfo = service_elem.attrib.get('extrainfo', '') if service_elem is not None else ''

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
df = pd.DataFrame(data)
if df.empty:
    print("No scan results found.")
else:
    df = df.sort_values(by="Port")
    print("Service Version Detection Result:\n")
    print(df.to_string(index=False))

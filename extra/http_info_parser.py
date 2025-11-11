#!/usr/bin/env python3
"""
HTTP Information Parser
======================

Parses Nmap XML output to extract HTTP-related script results including
titles, headers, methods, robots.txt, and security headers.

Expected Nmap commands:
  nmap -p 80,443 -sV --script http-title,http-headers target.com -oX - | python3 http_info_parser.py
  nmap -p 80 --script http-methods,http-robots.txt 192.168.1.100 -oX - | python3 http_info_parser.py
  nmap -p 443 --script http-security-headers,ssl-cert target.com -oX - | python3 http_info_parser.py
  nmap -p 80,8080,8443 --script "http-*" target.com -oX - | python3 http_info_parser.py

Complete command example:
  nmap -p 80,443 -sV --script http-title,http-headers,http-methods,http-robots.txt,http-security-headers 192.168.1.100 -oX - | python3 http_info_parser.py

Usage:
  nmap -p [ports] --script "http-*" [target] -oX - | python3 http_info_parser.py
"""

# Nmap command that generates this output:
# nmap -p 80 -sV --script http-title,http-headers,http-methods,http-robots.txt,http-security-headers 127.0.0.1 -oX -

import sys
import pandas as pd
import xml.etree.ElementTree as ET
import textwrap

# Read XML from stdin
xml_string = sys.stdin.read()
if not xml_string.strip():
    print("No XML input detected. Did you forget to pipe Nmap output?")
    sys.exit(1)

try:
    root = ET.fromstring(xml_string)
except ET.ParseError as e:
    print(f"Error parsing XML: {e}")
    sys.exit(1)

results = []

for host in root.findall("host"):
    for port in host.find("ports").findall("port"):
        for script in port.findall("script"):
            script_id = script.attrib.get("id", "unknown").strip()
            raw_output = script.attrib.get("output", "").strip()
            cleaned = raw_output.replace("\\n", "\n")  # Convert \n to real newlines
            output = cleaned if cleaned else "No output"
            results.append({
                "Script ID": script_id,
                "Output": output
            })

# Wrap output cleanly
def wrap_output(text, width=60, indent="    "):
    lines = text.splitlines()
    wrapped_lines = []
    for line in lines:
        wrapped = textwrap.wrap(line, width=width)
        if not wrapped:
            wrapped_lines.append(indent + "—")
        else:
            for wrapped_line in wrapped:
                wrapped_lines.append(indent + wrapped_line)
    return "\n".join(wrapped_lines)

df = pd.DataFrame(results)

if df.empty:
    print("No script results found.")
else:
    df["Output"] = df["Output"].apply(lambda x: wrap_output(x[:1000]))
    df["Script ID"] = df["Script ID"].str.ljust(24)

    print("\nHTTP Script Result Summary")
    print("-" * 80)
    for _, row in df.iterrows():
        print(f"{row['Script ID']}\n{row['Output']}\n")
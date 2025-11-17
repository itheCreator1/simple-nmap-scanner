#!/usr/bin/env python3
"""
NSE Script Output Parser
=======================
Parses Nmap NSE script results from XML output

Usage:
  nmap --script <scripts> <target> -oX - | python3 nse_parser.py
"""

import sys
from common_parser import read_and_parse_xml, safe_get_attrib

def parse_nse_output(root):
    """Parse NSE script results from Nmap XML"""
    results = []

    for host in root.findall('host'):
        ip_elem = host.find('address[@addrtype="ipv4"]')
        ip = safe_get_attrib(ip_elem, 'addr', 'N/A')

        ports_elem = host.find('ports')
        if ports_elem is None:
            continue

        for port in ports_elem.findall('port'):
            portid = safe_get_attrib(port, 'portid', 'N/A')

            for script in port.findall('script'):
                script_id = safe_get_attrib(script, 'id', 'unknown')
                output = safe_get_attrib(script, 'output', '')

                results.append({
                    'ip': ip,
                    'port': portid,
                    'script': script_id,
                    'output': output
                })

    return results

def format_output(results):
    """Format NSE results for display"""
    if not results:
        print("No NSE script results found.")
        return

    print("\nNSE Script Results")
    print("=" * 70)

    current_target = None

    for result in results:
        target = f"{result['ip']}:{result['port']}"

        if target != current_target:
            print(f"\n{target}")
            print("-" * 70)
            current_target = target

        print(f"\n[{result['script']}]")

        output_lines = result['output'].split('\n')
        for line in output_lines:
            if line.strip():
                print(f"  {line}")

def main():
    root = read_and_parse_xml()
    if root is None:
        sys.exit(1)

    results = parse_nse_output(root)
    format_output(results)

if __name__ == "__main__":
    main()

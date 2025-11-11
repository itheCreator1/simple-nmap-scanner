#!/usr/bin/env python3
"""
NSE Script Output Parser
=======================
Parses Nmap NSE script results from XML output

Usage:
  nmap --script <scripts> <target> -oX - | python3 nse_parser.py
"""

import sys
import xml.etree.ElementTree as ET

def parse_nse_output(xml_string):
    """Parse NSE script results from Nmap XML"""
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        return []
    
    results = []
    
    for host in root.findall('host'):
        ip_elem = host.find('address[@addrtype="ipv4"]')
        ip = ip_elem.attrib.get('addr') if ip_elem is not None else 'N/A'
        
        ports_elem = host.find('ports')
        if ports_elem is None:
            continue
            
        for port in ports_elem.findall('port'):
            portid = port.attrib.get('portid')
            
            for script in port.findall('script'):
                script_id = script.attrib.get('id')
                output = script.attrib.get('output', '')
                
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
    xml_input = sys.stdin.read()
    
    if not xml_input.strip():
        print("No input received. Pipe Nmap XML output to this script.", file=sys.stderr)
        sys.exit(1)
    
    results = parse_nse_output(xml_input)
    format_output(results)

if __name__ == "__main__":
    main()
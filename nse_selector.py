#!/usr/bin/env python3
"""
NSE Script Selector
==================
Maps detected services to appropriate Nmap NSE scripts based on service type and port.

Usage:
  python3 nse_selector.py --service http --port 80
  python3 nse_selector.py --service ssh --port 22 --target 192.168.1.100
"""

import json
import sys
from pathlib import Path
from typing import List, Dict

class NSESelector:
    def __init__(self, nse_db_path: str = "./extra/nse_scripts.json"):
        self.nse_db_path = Path(nse_db_path)
        self.nse_data = self._load_nse_database()
        
        # Map services to actual NSE scripts (not libraries)
        self.service_to_scripts = {
            'http': ['http-title', 'http-headers', 'http-methods'],
            'https': ['ssl-cert', 'ssl-enum-ciphers', 'http-title'],
            'https-alt': ['ssl-cert', 'ssl-enum-ciphers', 'http-title'],
            'ssh': ['ssh-hostkey', 'ssh-auth-methods', 'ssh2-enum-algos'],
            'ftp': ['ftp-anon', 'ftp-bounce', 'ftp-syst'],
            'smtp': ['smtp-commands', 'smtp-enum-users', 'smtp-open-relay'],
            'dns': ['dns-nsid', 'dns-recursion', 'dns-service-discovery'],
            'domain': ['dns-nsid', 'dns-recursion', 'dns-service-discovery'],
            'mysql': ['mysql-info', 'mysql-databases', 'mysql-users'],
            'postgresql': ['pgsql-databases'],
            'cslistener': ['http-title', 'http-headers'],
            'microsoft-ds': ['smb-os-discovery', 'smb-protocols', 'smb-security-mode'],
            'netbios-ssn': ['smb-os-discovery', 'smb-protocols', 'smb-security-mode'],
            'pop3': ['pop3-capabilities', 'pop3-ntlm-info'],
            'imap': ['imap-capabilities', 'imap-ntlm-info'],
            'vnc': ['vnc-info', 'vnc-title'],
            'telnet': ['telnet-ntlm-info', 'telnet-encryption'],
            'rdp': ['rdp-enum-encryption', 'rdp-ntlm-info'],
            'ms-wbt-server': ['rdp-enum-encryption', 'rdp-ntlm-info'],
            'ajp13': ['ajp-methods', 'ajp-request'],
            'redis': ['redis-info'],
            'mongodb': ['mongodb-info', 'mongodb-databases'],
            'snmp': ['snmp-info', 'snmp-sysdescr'],
            'ldap': ['ldap-rootdse', 'ldap-search'],
            'nfs': ['nfs-ls', 'nfs-showmount', 'nfs-statfs'],
            'rpcbind': ['rpcinfo'],
            'msrpc': ['msrpc-enum'],
            'oracle-tns': ['oracle-sid-brute', 'oracle-tns-version'],
            'sip': ['sip-methods', 'sip-enum-users'],
            'rtsp': ['rtsp-methods', 'rtsp-url-brute'],
            'ipp': ['ipp-info'],
            'upnp': ['upnp-info'],
        }
        
    def _load_nse_database(self) -> Dict:
        """Load NSE scripts database from JSON"""
        try:
            with open(self.nse_db_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: NSE database not found at {self.nse_db_path}", file=sys.stderr)
            return {}
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in NSE database: {e}", file=sys.stderr)
            return {}
    
    def get_scripts_for_service(self, service_name: str, port: int) -> List[Dict]:
        """
        Get recommended NSE scripts for a service/port combination
        
        Args:
            service_name: Service name (http, ssh, ftp, etc.)
            port: Port number
        
        Returns:
            List of dicts with script info
        """
        # Get scripts from mapping
        scripts = self.service_to_scripts.get(service_name.lower(), [])
        
        if not scripts:
            # Try to find similar service names
            for svc, svc_scripts in self.service_to_scripts.items():
                if service_name.lower() in svc or svc in service_name.lower():
                    scripts = svc_scripts
                    break
        
        # Return as list of dicts
        return [
            {
                'script': script,
                'description': f'NSE script for {service_name}',
                'relevance': 'exact'
            }
            for script in scripts
        ]

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Select appropriate NSE scripts for detected services'
    )
    parser.add_argument('--service', required=True, help='Service name')
    parser.add_argument('--port', type=int, required=True, help='Port number')
    parser.add_argument('--target', help='Target IP (for command generation)')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    selector = NSESelector()
    scripts = selector.get_scripts_for_service(args.service, args.port)
    
    if args.json:
        print(json.dumps(scripts, indent=2))
    else:
        print(f"\nRecommended NSE scripts for {args.service} on port {args.port}:")
        print("=" * 70)
        
        if not scripts:
            print("No matching NSE scripts found.")
        else:
            for i, script_info in enumerate(scripts, 1):
                print(f"\n{i}. {script_info['script']} ({script_info['relevance']})")
                print(f"   {script_info['description']}")
        
        if args.target and scripts:
            script_names = [s['script'] for s in scripts[:3]]
            print(f"\n{'=' * 70}")
            print("Suggested command (top 3 scripts):")
            print(f"nmap -sV --script {','.join(script_names)} -p {args.port} {args.target}")

if __name__ == "__main__":
    main()
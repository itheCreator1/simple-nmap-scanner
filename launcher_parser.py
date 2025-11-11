#!/usr/bin/env python3
"""
Real-Time Network Scan Parser
=============================

Professional-grade parser for network scan results with minimal colors.
Each color has a specific meaning for maximum clarity.

Usage:
  bash launcher.sh | python3 launcher_parser.py
"""

import sys
import re
import os
from datetime import datetime

class NetworkScanParser:
    def __init__(self):
        self.hosts_data = []
        self.ports_data = []
        self.services_data = []
        self.current_phase = "STARTING"
        self.current_host = None
        self.current_host_has_ports = False
        self.service_count = 0
        self.total_services = 0
        self.scan_start_time = datetime.now()
        self.setup_colors()
        self.compile_patterns()
        
    def setup_colors(self):
        """Setup minimal meaningful colors"""
        if os.isatty(sys.stdout.fileno()):
            self.GREEN = '\033[0;32m'  # Success/Found
            self.RED = '\033[0;31m'    # Error/Critical
            self.YELLOW = '\033[1;33m' # Warning
            self.BLUE = '\033[0;34m'   # Information
            self.BOLD = '\033[1m'      # Emphasis
            self.NC = '\033[0m'        # Reset
        else:
            self.GREEN = self.RED = self.YELLOW = ''
            self.BLUE = self.BOLD = self.NC = ''
    
    def compile_patterns(self):
        """Compile regex patterns for performance"""
        self.host_pattern = re.compile(
            r'\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+'
            r'([A-Fa-f0-9:]{17}|None)\s+(.*)'
        )
        self.port_pattern = re.compile(
            r'\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+'
            r'(\d+)\s+(\w+)\s+(\w+)\s+[\w\-]+\s+([\w\-]+)$'
        )
        self.service_pattern = re.compile(
            r'\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+'
            r'(\d+)\s+(\w+)\s+(\w+)\s+([\w\-]+)\s*(.*?)$'
        )
        self.host_scan_pattern = re.compile(
            r'Scanning ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
        )
        self.service_port_pattern = re.compile(
            r'Port ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(\d+)'
        )
        self.service_count_pattern = re.compile(
            r'Performing service detection on (\d+) open ports?'
        )
        
    def print_header(self):
        """Print main header"""
        print("─" * 80)
        print(f"{self.BOLD}NETWORK SECURITY ASSESSMENT{self.NC}")
        print(f"Started: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("─" * 80)
        
    def print_phase_header(self, phase):
        """Print phase header"""
        print(f"\n{self.BLUE}{phase}{self.NC}")
        print("─" * len(phase))
        
    def parse_host_discovery(self, line):
        """Parse host discovery results"""
        match = self.host_pattern.match(line.strip())
        if match:
            ip, mac, vendor = match.groups()
            if any(host['IP'] == ip for host in self.hosts_data):
                return
                
            host_info = {
                'IP': ip,
                'MAC': mac if mac != 'None' else '—',
                'Vendor': vendor.strip() if vendor.strip() and vendor.strip() != 'None' else '—'
            }
            self.hosts_data.append(host_info)
            
            vendor_text = f" [{host_info['Vendor']}]" if host_info['Vendor'] != '—' else ""
            print(f"{self.GREEN}+ Host discovered: {ip}{vendor_text}{self.NC}")
            
    def parse_port_scanning(self, line):
        """Parse port scanning results"""
        match = self.port_pattern.match(line.strip())
        if match:
            ip, port, protocol, state, service = match.groups()
            if state == 'open':
                port_info = {
                    'IP': ip,
                    'Port': int(port),
                    'Protocol': protocol,
                    'State': state,
                    'Service': service
                }
                
                if not any(p['IP'] == ip and p['Port'] == int(port) for p in self.ports_data):
                    self.ports_data.append(port_info)
                    print(f"  {self.GREEN}+ Port {ip}:{port} open ({service}){self.NC}")
                    self.current_host_has_ports = True
                    
    def parse_service_detection(self, line):
        """Parse service detection results"""
        match = self.service_pattern.match(line.strip())
        if match:
            ip, port, protocol, state, service, fingerprint = match.groups()
            service_info = {
                'IP': ip,
                'Port': int(port),
                'Protocol': protocol,
                'State': state,
                'Service': service,
                'Fingerprint': fingerprint.strip() if fingerprint.strip() else '—'
            }
            
            if not any(s['IP'] == ip and s['Port'] == int(port) for s in self.services_data):
                self.services_data.append(service_info)
                self.service_count += 1
                fp_text = f" -> {service_info['Fingerprint']}" if service_info['Fingerprint'] != '—' else ""
                print(f"  + Service {ip}:{port} ({service}){fp_text}")
                
    def print_host_discovery_summary(self):
        """Print host discovery summary"""
        print(f"\n{self.BOLD}HOST DISCOVERY COMPLETE{self.NC}")
        print("─" * 25)
        print(f"Total hosts found: {len(self.hosts_data)}")
        
        if self.hosts_data:
            print("\nDiscovered hosts:")
            for host in self.hosts_data:
                vendor = f" [{host['Vendor']}]" if host['Vendor'] != '—' else ""
                print(f"  • {host['IP']}{vendor}")
            
            vendors = [h['Vendor'] for h in self.hosts_data if h['Vendor'] != '—']
            if vendors:
                unique_vendors = len(set(vendors))
                print(f"\nDevice manufacturers: {unique_vendors}")
                
    def print_port_scanning_summary(self):
        """Print port scanning summary"""
        print(f"\n{self.BOLD}PORT SCANNING COMPLETE{self.NC}")
        print("─" * 25)
        print(f"Total open ports: {len(self.ports_data)}")
        
        if self.ports_data:
            host_ports = {}
            for port in self.ports_data:
                if port['IP'] not in host_ports:
                    host_ports[port['IP']] = []
                host_ports[port['IP']].append(f"{port['Port']}/{port['Service']}")
            
            print("\nOpen ports by host:")
            for ip in sorted(host_ports.keys()):
                ports = sorted(host_ports[ip], key=lambda x: int(x.split('/')[0]))
                print(f"  • {ip}: {', '.join(ports)}")
                
            hosts_with_ports = len(host_ports)
            total_hosts = len(self.hosts_data)
            print(f"\nHosts with open ports: {hosts_with_ports}/{total_hosts}")
        else:
            print("\nNo open ports discovered on any hosts")
            
    def print_service_detection_summary(self):
        """Print service detection summary"""
        print(f"\n{self.BOLD}SERVICE DETECTION COMPLETE{self.NC}")
        print("─" * 28)
        print(f"Services analyzed: {len(self.services_data)}")
        
        if self.services_data:
            interesting_services = [s for s in self.services_data if s['Fingerprint'] != '—']
            basic_services = [s for s in self.services_data if s['Fingerprint'] == '—']
            
            if interesting_services:
                print("\nDetailed fingerprints:")
                for service in sorted(interesting_services, key=lambda x: (x['IP'], x['Port'])):
                    print(f"  • {service['IP']}:{service['Port']} -> {service['Fingerprint']}")
            
            if basic_services:
                print("\nStandard services:")
                basic_summary = {}
                for service in basic_services:
                    svc_name = service['Service']
                    if svc_name not in basic_summary:
                        basic_summary[svc_name] = []
                    basic_summary[svc_name].append(f"{service['IP']}:{service['Port']}")
                
                for service_name in sorted(basic_summary.keys()):
                    locations = basic_summary[service_name]
                    print(f"  • {service_name}: {', '.join(sorted(locations))}")
        else:
            print("\nNo detailed service information available")
            
    def print_final_summary(self):
        """Print final summary"""
        print(f"\n{self.BOLD}{self.GREEN}+ SCAN COMPLETED{self.NC}")
        print("─" * 80)
        
        elapsed = (datetime.now() - self.scan_start_time).total_seconds()
        mins, secs = divmod(int(elapsed), 60)
        
        print(f"\n{self.BOLD}SCAN SUMMARY{self.NC}")
        print("─" * 20)
        print(f"Scan Duration    : {mins:02d}m {secs:02d}s")
        print(f"Hosts Discovered : {len(self.hosts_data)}")
        print(f"Open Ports Found : {len(self.ports_data)}")
        print(f"Services Detected: {len(self.services_data)}")
        
        if self.ports_data:
            print(f"\n{self.BOLD}SECURITY ASSESSMENT{self.NC}")
            print("─" * 25)
            
            risky_ports = [21, 22, 23, 80, 443, 3389, 5900, 8080, 8443]
            found_risky = [p for p in self.ports_data if p['Port'] in risky_ports]
            
            unique_hosts_with_ports = len(set(p['IP'] for p in self.ports_data))
            total_hosts = len(self.hosts_data)
            exposure_percent = (unique_hosts_with_ports / total_hosts * 100) if total_hosts > 0 else 0
            
            print(f"Network Exposure : {exposure_percent:.1f}% ({unique_hosts_with_ports}/{total_hosts} hosts)")
            
            if found_risky:
                print(f"{self.RED}Critical Services: {len(found_risky)} found{self.NC}")
                for port_info in sorted(found_risky, key=lambda x: (x['IP'], x['Port'])):
                    print(f"   L- {port_info['IP']}:{port_info['Port']} ({port_info['Service']})")
            else:
                print(f"{self.GREEN}Critical Services: None detected{self.NC}")
        
        interesting_services = [s for s in self.services_data if s['Fingerprint'] != '—']
        if interesting_services:
            print(f"\n{self.BOLD}SERVICE FINGERPRINTS{self.NC}")
            print("─" * 25)
            for service in sorted(interesting_services, key=lambda x: (x['IP'], x['Port'])):
                print(f"   {service['IP']}:{service['Port']}")
                print(f"   L- {service['Fingerprint']}")
        
        if len(self.hosts_data) > 1:
            vendors = [h['Vendor'] for h in self.hosts_data if h['Vendor'] != '—']
            unique_vendors = len(set(vendors))
            
            print(f"\n{self.BOLD}NETWORK TOPOLOGY{self.NC}")
            print("─" * 20)
            print(f"Device Vendors   : {unique_vendors} different manufacturers")
            
            if self.ports_data:
                common_services = {}
                for port in self.ports_data:
                    service = port['Service']
                    common_services[service] = common_services.get(service, 0) + 1
                
                if common_services:
                    top_service = max(common_services.items(), key=lambda x: x[1])
                    print(f"Common Services  : {top_service[0]} ({top_service[1]} instances)")
        
        print("\n" + "─" * 80)
        print(f"{self.BOLD}Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{self.NC}")
        print("─" * 80)
        
        # Network tree visualization
        self.print_network_tree()
        
        print()
        
    def print_network_tree(self):
        """Print network tree visualization"""
        print(f"\n{self.BOLD}NETWORK TREE{self.NC}")
        print("─" * 15)
        
        # Determine network CIDR (simplified)
        if self.hosts_data:
            # Get first three octets of first IP for network representation
            first_ip = self.hosts_data[0]['IP']
            network_base = '.'.join(first_ip.split('.')[:-1]) + '.0/24'
        else:
            network_base = "Unknown Network"
            
        print(f"Network: {network_base}")
        
        if not self.hosts_data:
            print("   └── (no hosts discovered)")
            return
            
        # Group data by host for tree structure
        host_tree = {}
        for host in self.hosts_data:
            ip = host['IP']
            host_tree[ip] = {
                'info': host,
                'ports': [],
                'services': []
            }
            
        # Add ports to hosts
        for port in self.ports_data:
            ip = port['IP']
            if ip in host_tree:
                host_tree[ip]['ports'].append(port)
                
        # Add services to hosts
        for service in self.services_data:
            ip = service['IP']
            if ip in host_tree:
                host_tree[ip]['services'].append(service)
        
        # Print tree structure
        sorted_hosts = sorted(host_tree.keys(), key=lambda x: tuple(map(int, x.split('.'))))
        
        for i, ip in enumerate(sorted_hosts):
            host_data = host_tree[ip]
            is_last_host = (i == len(sorted_hosts) - 1)
            host_prefix = "└──" if is_last_host else "├──"
            
            # Host line with vendor info
            vendor_info = f" [{host_data['info']['Vendor']}]" if host_data['info']['Vendor'] != '—' else ""
            print(f"   {host_prefix} {ip}{vendor_info}")
            
            # Ports for this host
            host_ports = host_data['ports']
            host_services = host_data['services']
            
            if not host_ports:
                continuation = "       " if is_last_host else "   │   "
                print(f"{continuation}└── (no open ports)")
                continue
                
            # Sort ports by port number
            sorted_ports = sorted(host_ports, key=lambda x: x['Port'])
            
            for j, port in enumerate(sorted_ports):
                is_last_port = (j == len(sorted_ports) - 1)
                continuation = "       " if is_last_host else "   │   "
                port_prefix = "└──" if is_last_port else "├──"
                
                print(f"{continuation}{port_prefix} {port['Port']}/{port['Protocol']} ({port['Service']})")
                
                # Services for this port
                port_services = [s for s in host_services if s['Port'] == port['Port']]
                
                if port_services:
                    service = port_services[0]  # Should only be one service per port
                    if service['Fingerprint'] != '—':
                        service_continuation = "           " if is_last_host else "   │       "
                        if is_last_port:
                            service_continuation = "           " if is_last_host else "   │       "
                        else:
                            service_continuation = "   │       " if not is_last_host else "           "
                            
                        print(f"{service_continuation}└── {service['Fingerprint']}")
        
    def handle_host_transition(self):
        """Handle transition between hosts"""
        if (self.current_host and 
            not self.current_host_has_ports and 
            self.current_phase == "PORT_SCANNING"):
            print("  (no open ports)")
            
    def process_line(self, line):
        """Process each line of input"""
        if not line or len(line.strip()) == 0:
            return
            
        if "=== HOST DISCOVERY ===" in line:
            self.current_phase = "HOST_DISCOVERY"
            self.print_phase_header("HOST DISCOVERY")
            return
            
        elif "=== PORT SCANNING ===" in line:
            self.current_phase = "PORT_SCANNING"
            self.print_host_discovery_summary()
            self.print_phase_header("PORT SCANNING")
            return
            
        elif "=== SERVICE DETECTION ===" in line:
            self.handle_host_transition()
            self.current_phase = "SERVICE_DETECTION"
            self.total_services = len(self.ports_data)
            self.service_count = 0
            self.print_port_scanning_summary()
            self.print_phase_header("SERVICE DETECTION")
            return
            
        elif "Scan complete!" in line:
            self.current_phase = "COMPLETE"
            self.print_service_detection_summary()
            self.print_final_summary()
            return
        
        host_match = self.host_scan_pattern.search(line)
        if host_match:
            self.handle_host_transition()
            self.current_host = host_match.group(1)
            self.current_host_has_ports = False
            print(f"\n-> Scanning {self.current_host}...")
            return
            
        service_match = self.service_port_pattern.search(line)
        if service_match:
            ip, port = service_match.groups()
            print(f"\n-> Analyzing {ip}:{port}...")
            return
        
        count_match = self.service_count_pattern.search(line)
        if count_match:
            self.total_services = int(count_match.group(1))
            return
        
        try:
            if self.current_phase == "HOST_DISCOVERY":
                self.parse_host_discovery(line)
            elif self.current_phase == "PORT_SCANNING":
                self.parse_port_scanning(line)
            elif self.current_phase == "SERVICE_DETECTION":
                self.parse_service_detection(line)
        except Exception:
            pass

def main():
    """Main function"""
    parser = NetworkScanParser()
    parser.print_header()
    
    try:
        for line in sys.stdin:
            parser.process_line(line.rstrip())
                
        if parser.current_phase != "COMPLETE":
            print(f"\n{parser.YELLOW}! Scan interrupted - showing partial results{parser.NC}")
            
            if parser.current_phase == "PORT_SCANNING" and parser.hosts_data:
                parser.print_host_discovery_summary()
            elif parser.current_phase == "SERVICE_DETECTION":
                if parser.hosts_data:
                    parser.print_host_discovery_summary()
                if parser.ports_data:
                    parser.print_port_scanning_summary()
                    
            parser.print_final_summary()
            
    except KeyboardInterrupt:
        print(f"\n{parser.YELLOW}! Scan interrupted by user{parser.NC}")
        if parser.hosts_data or parser.ports_data or parser.services_data:
            parser.print_final_summary()
        
    except BrokenPipeError:
        sys.stderr.close()
        
    except Exception as e:
        print(f"\n{parser.RED}X Parser error: {str(e)[:100]}{parser.NC}")
        sys.exit(1)

if __name__ == "__main__":
    main()

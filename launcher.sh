#!/usr/bin/env bash
# Simple Network Scan Orchestrator
# Discovers hosts, scans ports, detects services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== HOST DISCOVERY ==="
host_output=$("${SCRIPT_DIR}/active_host_scan.sh")
echo "$host_output"

# Extract active host IPs - skip header and empty lines, handle whitespace
active_hosts=$(echo "$host_output" | \
    grep -v "Active Hosts:" | \
    grep -v "IP.MAC.Vendor" | \
    grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    awk '{print $1}' | \
    sed 's/^[[:space:]]*//' | \
    sort -u)

if [[ -z "$active_hosts" ]]; then
    echo "No active hosts found"
    exit 0
fi

echo -e "\n=== PORT SCANNING ==="

# Store all host:port combinations for service detection
declare -a host_port_pairs=()

# Convert to array properly
declare -a hosts_array=()
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        hosts_array+=("$line")
    fi
done <<< "$active_hosts"

for host in "${hosts_array[@]}"; do
    if [[ -z "$host" ]]; then
        continue
    fi
    
    echo -e "\nScanning $host..."
    
    # Run port scan and capture output
    port_output=$("${SCRIPT_DIR}/active_port_scan.sh" "$host")
    echo "$port_output"
    
    # Extract open ports - handle cases with no results
    ip_lines=$(echo "$port_output" | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || true)
    
    if [[ -z "$ip_lines" ]]; then
        open_ports=""
    else
        open_lines=$(echo "$ip_lines" | grep "open" || true)
        if [[ -z "$open_lines" ]]; then
            open_ports=""
        else
            port_numbers=$(echo "$open_lines" | awk '{print $2}')
            open_ports=$(echo "$port_numbers" | sort -n -u)
        fi
    fi
    
    if [[ -n "$open_ports" ]]; then
        port_count=$(echo "$open_ports" | wc -l)
        echo "Found $port_count open port(s) on $host"
        
        # Convert ports to array and add to host_port_pairs
        declare -a ports_array=()
        while IFS= read -r port_line; do
            if [[ -n "$port_line" ]]; then
                ports_array+=("$port_line")
            fi
        done <<< "$open_ports"
        
        for port in "${ports_array[@]}"; do
            if [[ -n "$port" ]]; then
                host_port_pairs+=("$host:$port")
            fi
        done
    else
        echo "No open ports found on $host"
    fi
done

echo -e "\n=== SERVICE DETECTION ==="
if [[ ${#host_port_pairs[@]} -eq 0 ]]; then
    echo "No open ports found on any hosts. Service detection skipped."
else
    echo "Performing service detection on ${#host_port_pairs[@]} open port(s)..."
    for host_port in "${host_port_pairs[@]}"; do
        IFS=':' read -r host port <<< "$host_port"
        echo -e "\nPort ${host}:${port}"
        "${SCRIPT_DIR}/single_port_service_scan.sh" "$host" "$port"
    done
fi

echo -e "\nScan complete!"

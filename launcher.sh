#!/usr/bin/env bash
# Simple Network Scan Orchestrator
# Discovers hosts, scans ports, detects services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${SCRIPT_DIR}/.venv"

# Check if virtual environment exists
if [[ ! -f "${VENV_PATH}/bin/activate" ]]; then
    echo "ERROR: Virtual environment not found at ${VENV_PATH}" >&2
    echo "Run: ./setup.sh" >&2
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "ERROR: nmap is not installed" >&2
    echo "Run: ./setup.sh (it will show install instructions)" >&2
    exit 1
fi

echo "=== HOST DISCOVERY ==="
host_output=$("${SCRIPT_DIR}/active_host_scan.sh")
echo "$host_output"

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

declare -a host_port_pairs=()
declare -a host_port_service=()

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

    port_output=$("${SCRIPT_DIR}/active_port_scan.sh" "$host")
    echo "$port_output"

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

        declare -a ports_array=()
        while IFS= read -r port_line; do
            if [[ -n "$port_line" ]]; then
                ports_array+=("$port_line")
            fi
        done <<< "$open_ports"

        for port in "${ports_array[@]}"; do
            if [[ -n "$port" ]]; then
                service=$(echo "$open_lines" | grep -w "$port" | awk '{print $6}')
                host_port_pairs+=("$host:$port")
                host_port_service+=("$host:$port:$service")
            fi
        done
    else
        echo "No open ports found on $host"
    fi
done

echo -e "\n=== NSE SCRIPT EXECUTION ==="
if [[ ${#host_port_service[@]} -eq 0 ]]; then
    echo "No services to scan with NSE scripts."
else
    echo "Running NSE scripts on ${#host_port_service[@]} service(s)..."
    for entry in "${host_port_service[@]}"; do
        IFS=':' read -r host port service <<< "$entry"
        echo -e "\n--- NSE: ${host}:${port} (${service}) ---"
        "${SCRIPT_DIR}/nse_runner.sh" "$host" "$port" "$service" | python3 "${SCRIPT_DIR}/nse_parser.py"
    done
fi

echo -e "\nScan complete!"

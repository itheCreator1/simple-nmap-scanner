# simple-nmap-scanner

Network scanning toolkit with automated discovery, port scanning, and service detection.

## Usage

```bash
# Full automated scan with real-time output
./launcher.sh | python3 launcher_parser.py

# Individual components
./active_host_scan.sh [network]
./active_port_scan.sh [target]
./single_port_service_scan.sh [ip] [port]
./http_info_scan.sh [ip]
```

## Files

- `launcher.sh` - Main orchestrator
- `launcher_parser.py` - Real-time output formatter
- `active_host_scan.sh` + `active_host_parser.py` - Host discovery
- `active_port_scan.sh` + `active_port_parser.py` - Port scanning  
- `single_port_service_scan.sh` + `single_port_service_scan_parser.py` - Service detection
- `http_info_scan.sh` + `http_info_parser.py` - HTTP enumeration

## Setup

```bash
chmod +x *.sh
pip install pandas
```

Update venv path in .sh files if needed.
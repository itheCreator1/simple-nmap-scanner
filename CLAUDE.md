# CLAUDE.md - AI Assistant Development Guide

## Project Overview

**simple-nmap-scanner** is a modular network reconnaissance toolkit built on Nmap. It provides automated network discovery, port scanning, service detection, and NSE (Nmap Scripting Engine) execution with real-time formatted output.

### Key Features
- Modular component architecture - each component can run standalone
- Automatic LAN network detection and scanning
- Real-time output parsing with professional formatting
- Pandas-based parsers for human-readable results
- NSE script automation with service-aware script selection
- Network tree visualization and security assessment

### Technology Stack
- **Shell Scripts**: Bash for Nmap orchestration and execution
- **Python 3**: XML parsing, data formatting, and output processing
- **Nmap**: Network scanning engine
- **Dependencies**: pandas (Python), virtual environment (.venv)

---

## Codebase Structure

```
simple-nmap-scanner/
├── launcher.sh                          # Main orchestrator script
├── launcher_parser.py                   # Real-time comprehensive parser
├── active_host_scan.sh                  # Host discovery component
├── active_host_parser.py                # Host discovery XML parser
├── active_port_scan.sh                  # Port scanning component
├── active_port_parser.py                # Port scan XML parser
├── single_port_service_scan.sh          # [DEPRECATED] Service detection
├── single_port_service_scan_parser.py   # [DEPRECATED] Service parser
├── nse_runner.sh                        # NSE script executor
├── nse_selector.py                      # Service-to-NSE script mapper
├── nse_parser.py                        # NSE output formatter
├── extra/
│   ├── nse_scripts.json                 # NSE script database
│   └── claudecode-codeReview            # Code review notes
├── .venv/                               # Python virtual environment
├── .gitignore                           # Python/IDE ignores
└── README.md                            # User documentation
```

### Component Categories

1. **Orchestration**: `launcher.sh`, `launcher_parser.py`
2. **Host Discovery**: `active_host_scan.sh`, `active_host_parser.py`
3. **Port Scanning**: `active_port_scan.sh`, `active_port_parser.py`
4. **NSE Execution**: `nse_runner.sh`, `nse_selector.py`, `nse_parser.py`
5. **Resources**: `extra/nse_scripts.json`

---

## Architecture and Data Flow

### 1. Scan Workflow (launcher.sh)

```
launcher.sh pipeline:
1. Host Discovery       → active_host_scan.sh → Parse IPs
2. Port Scanning        → For each host: active_port_scan.sh → Collect ports
3. NSE Execution        → For each port+service: nse_runner.sh → Run scripts
4. Real-time Parsing    → launcher_parser.py → Formatted output
```

### 2. Component Independence

Each component can run standalone:
```bash
# Host discovery only
./active_host_scan.sh [network]

# Port scan specific target
./active_port_scan.sh 192.168.1.100

# Run NSE scripts on service
./nse_runner.sh 192.168.1.100 80 http | python3 nse_parser.py
```

### 3. Parser Architecture

**Pattern**: Shell script → Nmap XML output (`-oX -`) → Python XML parser → Formatted output

All parsers follow this structure:
- Read XML from stdin (`sys.stdin.read()`)
- Parse with `xml.etree.ElementTree`
- Extract data into structured format
- Output formatted results (pandas DataFrames or custom formatting)

---

## Development Workflows

### Setting Up Development Environment

```bash
# 1. Clone repository
git clone <repository-url>
cd simple-nmap-scanner

# 2. Create virtual environment
python3 -m venv .venv

# 3. Activate virtual environment
source .venv/bin/activate

# 4. Install dependencies
pip install pandas

# 5. Make scripts executable
chmod +x *.sh

# 6. Update venv path in scripts if needed
# Edit .sh files to match your .venv location
```

### Running Full Scan

```bash
# Full automated scan with real-time output
./launcher.sh | python3 launcher_parser.py
```

### Testing Individual Components

```bash
# Test host discovery
./active_host_scan.sh 192.168.1.0/24

# Test port scanning
./active_port_scan.sh 192.168.1.1

# Test NSE script selection
python3 nse_selector.py --service http --port 80

# Test NSE execution
./nse_runner.sh 192.168.1.1 80 http | python3 nse_parser.py
```

---

## Code Conventions and Patterns

### Bash Scripts

#### Standard Header Pattern
```bash
#!/usr/bin/env bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures
```

#### Virtual Environment Activation
All scripts activate the Python venv:
```bash
source .venv/bin/activate
```

#### Error Handling in nse_runner.sh
When no scripts found, output minimal valid XML:
```bash
echo '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
```

#### Nmap Output Format
Always use XML output for parsing:
```bash
nmap [options] [target] -oX -
```

### Python Parsers

#### Standard Structure
```python
#!/usr/bin/env python3
"""
Module Description
==================
Usage examples and documentation
"""

import sys
import xml.etree.ElementTree as ET
import pandas as pd  # For tabular parsers

# Read XML from stdin
xml_string = sys.stdin.read()
root = ET.fromstring(xml_string)

# Parse and extract data
data = []
for element in root.findall('xpath'):
    # Extract information
    data.append({...})

# Format and output
```

#### Parser Patterns

**Tabular Output (active_host_parser.py, active_port_parser.py)**:
- Use pandas DataFrames
- `df.to_string(index=False)` for output
- Clean column names (IP, Port, Service, etc.)

**Formatted Output (launcher_parser.py, nse_parser.py)**:
- Real-time streaming parsing
- ANSI color codes for TTY detection
- Progressive output with phase tracking
- Summary sections with statistics

#### Color Usage (launcher_parser.py)
```python
GREEN  # Success/Found items
RED    # Errors/Critical services
YELLOW # Warnings
BLUE   # Section headers/Information
BOLD   # Emphasis
```

### NSE Script Selection Pattern

**File**: `nse_selector.py`

Maps service names to relevant NSE scripts:
```python
self.service_to_scripts = {
    'http': ['http-title', 'http-headers', 'http-methods'],
    'ssh': ['ssh-hostkey', 'ssh-auth-methods', 'ssh2-enum-algos'],
    # ... service mappings
}
```

**Return format**: List of dicts with script, description, relevance

---

## Key Implementation Details

### 1. Host Discovery (active_host_scan.sh)

**Nmap command**: `nmap -sn -T4 [cidr] -oX -`
- `-sn`: Ping scan only (no port scan)
- `-T4`: Aggressive timing
- Auto-detects local network if no CIDR provided

**Parser extracts**:
- IP addresses (IPv4)
- MAC addresses
- Vendor information from MAC

### 2. Port Scanning (active_port_scan.sh)

**Nmap command**: `nmap --top-ports 1000 -Pn -T4 [options] [target] -oX -`
- `--top-ports 1000`: Scan 1000 most common ports
- `-Pn`: Skip host discovery (assume host is up)
- `--host-timeout 30s`: Maximum time per host
- `--max-rtt-timeout 2s`: RTT timeout
- `--max-scan-delay 1s`: Delay between probes

**Parser extracts**:
- IP, Port, Protocol, State, Service name

### 3. Service Detection (DEPRECATED)

**Note**: `single_port_service_scan.sh` functionality has been removed from launcher.sh (see lines 85-95, commented out). NSE execution now handles service detection.

### 4. NSE Execution (nse_runner.sh)

**Workflow**:
1. Call `nse_selector.py` to get relevant scripts for service
2. Extract top 3 script names from JSON output
3. Run: `nmap -sV -Pn -T4 --script [scripts] -p [port] [target] -oX -`
4. If no scripts found, output minimal XML to prevent parser errors

**Nmap options**:
- `-sV`: Version detection
- `--script`: Comma-separated NSE script names

### 5. Launcher Orchestration (launcher.sh)

**Data collection**:
```bash
declare -a host_port_pairs=()      # Array of "ip:port"
declare -a host_port_service=()    # Array of "ip:port:service"
```

**Phase transitions**:
1. Host discovery → Extract active IPs
2. Port scanning → Build host:port:service tuples
3. NSE execution → Run scripts for each service

### 6. Real-time Parser (launcher_parser.py)

**State machine approach**:
- Tracks current phase: HOST_DISCOVERY, PORT_SCANNING, NSE_SCRIPT_EXECUTION, COMPLETE
- Regex patterns compiled for performance
- Buffers data for summary sections
- Generates multiple outputs:
  - Real-time progress updates
  - Phase summaries (hosts found, ports discovered)
  - Final comprehensive summary
  - Network tree visualization
  - Security assessment

**Key features**:
- Line-by-line streaming parsing
- Context preservation (current host, current port)
- Duplicate detection
- Statistical analysis (exposure %, common services)

---

## Dependencies and Environment

### Python Dependencies
- **pandas**: DataFrame creation and tabular output
  - Used in: `active_host_parser.py`, `active_port_parser.py`, `single_port_service_scan_parser.py`

### System Requirements
- **Nmap**: Network scanner
- **Python 3**: Parser scripts
- **Bash**: Shell scripts
- **Standard Linux utilities**: grep, awk, sed, sort

### Virtual Environment
All bash scripts expect `.venv` in script directory:
```bash
source .venv/bin/activate
```

**Customization**: Update `source .venv/bin/activate` lines if using different venv location.

---

## File References and Line Numbers

### Important Code Locations

**launcher.sh**:
- Lines 9-11: Host discovery execution
- Lines 13-19: Active host extraction
- Lines 28-83: Port scanning loop
- Lines 97-107: NSE execution loop
- Lines 85-95: Commented out service detection (deprecated)

**launcher_parser.py**:
- Lines 32-43: Color setup with TTY detection
- Lines 45-67: Regex pattern compilation
- Lines 81-97: Host discovery parsing
- Lines 99-116: Port scanning parsing
- Lines 209-272: Final summary generation
- Lines 279-363: Network tree visualization

**nse_selector.py**:
- Lines 23-60: Service to NSE script mapping dictionary
- Lines 74-103: Script selection logic with fallback

**nse_runner.sh**:
- Lines 17-19: NSE script selection via Python
- Lines 21-25: Minimal XML output when no scripts found
- Line 27: Nmap NSE execution

---

## Git and Version Control

### Current Branch
- Development branch: `claude/claude-md-mi3b586wwzbzo9s0-01XhuryRQ4sjtSub3vY51yij`
- Main branch: (not specified in git status)

### Recent Changes (from git log)
1. **3ea1e87**: Removed single port service scan (deprecated)
2. **cef0a2c**: Output minimal valid XML when no NSE scripts found
3. **fc6941d**: Added NSE functionality
4. **f14fe62**: Created NSE script database (nse_scripts.json)
5. **f937992**: Updated README

### Gitignore Highlights
- Python artifacts: `__pycache__/`, `*.pyc`, `.venv/`
- IDE: `.vscode/`, `.idea/`, `.cursorignore`
- Environment: `.env`, `.envrc`

---

## Security and Best Practices

### Security Considerations

1. **Network Scanning Ethics**
   - This tool performs active network reconnaissance
   - Only scan networks you own or have explicit permission to test
   - Unauthorized scanning may be illegal in your jurisdiction

2. **Script Injection Prevention**
   - All user inputs are validated
   - Nmap commands use proper quoting
   - XML parsing prevents injection attacks

3. **Privilege Requirements**
   - Some Nmap scans require root/sudo
   - SYN scans (`-sS`) require elevated privileges
   - Current scans use `-sn`, `-Pn`, `-sV` which may need privileges

### Best Practices

1. **Modular Testing**
   - Test components individually before full scan
   - Use small network ranges for initial testing
   - Validate parsers with known Nmap XML output

2. **Error Handling**
   - Bash scripts use `set -euo pipefail`
   - Python parsers have try-except blocks
   - Empty results handled gracefully

3. **Performance**
   - Timing template `-T4` balances speed and reliability
   - Timeouts prevent hung scans
   - Top 1000 ports instead of all 65535

---

## Common Modification Scenarios

### Adding a New NSE Script Mapping

**File**: `nse_selector.py`

```python
# Lines 23-60: Add new service mapping
self.service_to_scripts = {
    'your-service': ['nse-script-1', 'nse-script-2'],
    # ... existing mappings
}
```

### Changing Port Scan Range

**File**: `active_port_scan.sh`

```bash
# Line 13: Modify --top-ports value
nmap --top-ports 5000 -Pn -T4 \  # Scan top 5000 instead of 1000
```

Or scan specific ports:
```bash
nmap -p 22,80,443,3306 -Pn -T4 "$target" -oX -
```

### Customizing Output Colors

**File**: `launcher_parser.py`

```python
# Lines 32-43: Modify color codes
self.GREEN = '\033[0;32m'   # Change to bright green: '\033[1;32m'
self.RED = '\033[0;31m'     # Change color scheme
```

### Adding New Parser

**Template**:
```python
#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET

xml_string = sys.stdin.read()
root = ET.fromstring(xml_string)

# Your parsing logic here
for element in root.findall('your/xpath'):
    # Extract and process data
    pass
```

**Integration**:
```bash
nmap [options] [target] -oX - | python3 your_parser.py
```

### Modifying Scan Timing

**Files**: All `.sh` scripts with nmap commands

```bash
# Change from -T4 (aggressive) to -T2 (polite)
nmap -T2 [options]  # Slower but less intrusive

# Or -T5 (insane) for maximum speed
nmap -T5 [options]  # Fastest but may miss results
```

### Adding Custom Summary Statistics

**File**: `launcher_parser.py`

```python
# Add to print_final_summary() method (lines 209-272)
def print_final_summary(self):
    # ... existing code

    # Add your custom statistics
    print(f"\n{self.BOLD}CUSTOM METRICS{self.NC}")
    print("─" * 20)
    # Your analysis here
```

---

## Testing and Validation

### Manual Testing Checklist

```bash
# 1. Test host discovery
./active_host_scan.sh 127.0.0.1/32
# Expected: Should find localhost

# 2. Test port scanning
./active_port_scan.sh 127.0.0.1
# Expected: Should find open ports

# 3. Test NSE selector
python3 nse_selector.py --service http --port 80
# Expected: Should list http-related NSE scripts

# 4. Test full pipeline
./launcher.sh | python3 launcher_parser.py
# Expected: Complete formatted scan output
```

### Debugging Tips

1. **View raw XML output**:
   ```bash
   nmap -sn 192.168.1.0/24 -oX - > output.xml
   cat output.xml
   ```

2. **Test parser with saved XML**:
   ```bash
   cat output.xml | python3 active_host_parser.py
   ```

3. **Check Python environment**:
   ```bash
   source .venv/bin/activate
   python3 -c "import pandas; print(pandas.__version__)"
   ```

4. **Verbose nmap output**:
   ```bash
   nmap -v -sn [target]  # Add -v for verbose
   ```

### Error Messages

**"No active hosts found"**:
- Check network connectivity
- Verify CIDR notation
- Try with sudo if needed

**"ImportError: No module named 'pandas'"**:
- Activate venv: `source .venv/bin/activate`
- Install pandas: `pip install pandas`

**"nmap: command not found"**:
- Install nmap: `sudo apt install nmap` (Debian/Ubuntu)

---

## AI Assistant Guidelines

### When Modifying This Project

1. **Preserve Modularity**: Each component should remain standalone
2. **Maintain Parser Pattern**: Shell → XML → Python parser → Output
3. **Update Documentation**: Keep README.md and this file in sync
4. **Test Components**: Validate individual scripts before integration
5. **Follow Conventions**: Use established patterns for consistency

### Code Review Focus Areas

1. **XML Parsing Safety**: Validate XML structure before parsing
2. **Bash Quoting**: Ensure proper quoting in shell scripts
3. **Error Handling**: Graceful degradation on empty results
4. **Performance**: Consider scan time vs. thoroughness tradeoffs
5. **Output Formatting**: Maintain clean, readable output

### Common Tasks

**Add a new scan component**:
1. Create `component_scan.sh` (Bash script with nmap command)
2. Create `component_parser.py` (Python XML parser)
3. Integrate into `launcher.sh` if needed
4. Update this documentation

**Modify scan parameters**:
1. Locate relevant `.sh` file
2. Modify nmap options
3. Test with small target set
4. Verify parser still works

**Extend NSE coverage**:
1. Update `nse_selector.py` service mappings
2. Test with `nse_selector.py --service <name> --port <port>`
3. Verify `nse_runner.sh` executes correctly

### Questions to Ask Before Changes

- Does this maintain component independence?
- Will the XML output format change?
- Do parsers need updating?
- Is error handling adequate?
- Have you tested with edge cases (no hosts, no ports, timeouts)?

---

## Deprecated Features

### single_port_service_scan.sh
**Status**: Deprecated (removed from launcher.sh)
**Lines**: launcher.sh:85-95 (commented out)
**Reason**: Service detection now integrated into NSE execution phase
**Migration**: Use NSE scripts for detailed service information

---

## Additional Resources

### Nmap Documentation
- Output formats: https://nmap.org/book/output.html
- NSE scripts: https://nmap.org/nsedoc/
- Timing and performance: https://nmap.org/book/performance.html

### Python XML Parsing
- xml.etree.ElementTree: https://docs.python.org/3/library/xml.etree.elementtree.html

### Pandas Output Formatting
- to_string(): https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.to_string.html

---

## Quick Reference

### File Purposes
| File | Purpose | Input | Output |
|------|---------|-------|--------|
| launcher.sh | Orchestrator | Network/auto-detect | Scan phases |
| launcher_parser.py | Real-time formatter | launcher.sh output | Formatted report |
| active_host_scan.sh | Host discovery | CIDR | Nmap XML |
| active_host_parser.py | Host formatter | XML | IP/MAC/Vendor table |
| active_port_scan.sh | Port scanner | IP address | Nmap XML |
| active_port_parser.py | Port formatter | XML | Port/Service table |
| nse_runner.sh | NSE executor | IP, Port, Service | Nmap NSE XML |
| nse_selector.py | Script mapper | Service name | NSE script list |
| nse_parser.py | NSE formatter | XML | Formatted NSE results |

### Common Commands
```bash
# Full scan
./launcher.sh | python3 launcher_parser.py

# Individual components
./active_host_scan.sh [network]
./active_port_scan.sh [target]
./nse_runner.sh [ip] [port] [service] | python3 nse_parser.py

# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install pandas
chmod +x *.sh
```

---

**Document Version**: 1.0
**Last Updated**: 2025-11-17
**Maintainer**: AI Assistant Analysis

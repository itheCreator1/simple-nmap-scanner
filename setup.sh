#!/usr/bin/env bash
set -euo pipefail

echo "=== Simple Nmap Scanner Setup ==="
echo ""

# Check Python
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not installed"
    echo "Install Python 3: https://www.python.org/downloads/"
    exit 1
fi
echo "✓ Python 3 found: $(python3 --version)"

# Check nmap
echo "Checking nmap installation..."
if ! command -v nmap &> /dev/null; then
    echo "ERROR: nmap not installed"
    echo ""
    echo "Install nmap:"
    echo "  Debian/Ubuntu: sudo apt install nmap"
    echo "  Fedora:        sudo dnf install nmap"
    echo "  macOS:         brew install nmap"
    echo "  Arch:          sudo pacman -S nmap"
    exit 1
fi
echo "✓ nmap found: $(nmap --version | head -n1)"

# Create venv
echo ""
echo "Setting up virtual environment..."
if [[ -d .venv ]]; then
    echo "Virtual environment already exists, skipping creation"
else
    python3 -m venv .venv
    echo "✓ Virtual environment created"
fi

# Activate and install
source .venv/bin/activate
echo ""
echo "Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "✓ Dependencies installed"

# Make scripts executable
echo ""
echo "Making scripts executable..."
chmod +x *.sh
echo "✓ Scripts are executable"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the scanner:"
echo "  ./launcher.sh | python3 launcher_parser.py"
echo ""
echo "To run individual components:"
echo "  ./active_host_scan.sh [network]"
echo "  ./active_port_scan.sh [target]"
echo ""

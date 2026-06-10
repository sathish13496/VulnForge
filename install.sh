#!/bin/bash

# ╔══════════════════════════════════════════╗
# ║  VulnForge — Installation Script        ║
# ║  Linux Security Misconfiguration Scanner ║
# ╚══════════════════════════════════════════╝

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     🛡️  VulnForge Installer v1.0.0      ║"
echo "  ║     Security Misconfiguration Framework  ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python version
echo -e "${YELLOW}[1/5]${NC} Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
        echo -e "  ${GREEN}✓${NC} Python $PYTHON_VERSION found"
    else
        echo -e "  ${RED}✗${NC} Python 3.10+ required, found $PYTHON_VERSION"
        echo -e "  Install: ${CYAN}sudo apt install python3.10${NC}"
        exit 1
    fi
else
    echo -e "  ${RED}✗${NC} Python 3 not found"
    echo -e "  Install: ${CYAN}sudo apt install python3 python3-pip python3-venv${NC}"
    exit 1
fi

# Check Nmap
echo -e "${YELLOW}[2/5]${NC} Checking Nmap installation..."
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version 2>&1 | head -1)
    echo -e "  ${GREEN}✓${NC} $NMAP_VERSION"
else
    echo -e "  ${RED}✗${NC} Nmap not found"
    echo -e "  Installing Nmap..."
    
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y nmap
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap
    elif command -v brew &> /dev/null; then
        brew install nmap
    else
        echo -e "  ${RED}Please install Nmap manually: https://nmap.org/download.html${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} Nmap installed"
fi

# Create virtual environment
echo -e "${YELLOW}[3/5]${NC} Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "  ${GREEN}✓${NC} Virtual environment created"
else
    echo -e "  ${GREEN}✓${NC} Virtual environment already exists"
fi

source venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}[4/5]${NC} Installing Python dependencies..."
pip install --upgrade pip > /dev/null 2>&1
pip install -e . > /dev/null 2>&1
echo -e "  ${GREEN}✓${NC} Dependencies installed"

# Create data directories
echo -e "${YELLOW}[5/5]${NC} Setting up data directories..."
mkdir -p data/nvd data/rules reports
echo -e "  ${GREEN}✓${NC} Data directories created"

# Done
echo ""
echo -e "${GREEN}  ╔══════════════════════════════════════════╗"
echo -e "  ║  ✅  Installation Complete!               ║"
echo -e "  ╠══════════════════════════════════════════╣"
echo -e "  ║                                          ║"
echo -e "  ║  Start Web UI:                           ║"
echo -e "  ║    source venv/bin/activate               ║"
echo -e "  ║    vulnforge --web                       ║"
echo -e "  ║                                          ║"
echo -e "  ║  CLI Scan:                               ║"
echo -e "  ║    vulnforge scan -t 192.168.1.100       ║"
echo -e "  ║                                          ║"
echo -e "  ║  Update CVE Database:                    ║"
echo -e "  ║    vulnforge --update-db                 ║"
echo -e "  ║                                          ║"
echo -e "  ╚══════════════════════════════════════════╝${NC}"
echo ""

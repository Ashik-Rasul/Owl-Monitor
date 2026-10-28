#!/usr/bin/env bash
# ==============================================================================
# Owl Monitor — Automated Setup & Dependency Installer
# ==============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}       OWL MONITOR — ENVIRONMENT SETUP              ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Detect Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python 3 is not installed on this system.${NC}"
    echo -e "${YELLOW}Please install Python 3 using your package manager (e.g., sudo apt install python3).${NC}"
    exit 1
fi

PY_VERSION=$(python3 --version)
echo -e "${GREEN}[OK] Found ${PY_VERSION}${NC}"

# 2. Check for python3-venv / venv support
echo -e "${BLUE}[INFO] Checking Python virtual environment (venv) module...${NC}"
if ! python3 -m venv --help &> /dev/null; then
    echo -e "${RED}[ERROR] 'python3-venv' module is missing.${NC}"
    echo -e "${YELLOW}Please install it via your OS package manager, for example:${NC}"
    echo -e "       sudo apt update && sudo apt install python3-venv"
    exit 1
fi
echo -e "${GREEN}[OK] python3-venv module is available.${NC}"

# 3. Create .venv if necessary
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${BLUE}[INFO] Creating virtual environment in ./${VENV_DIR}...${NC}"
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}[OK] Virtual environment created successfully.${NC}"
else
    echo -e "${GREEN}[OK] Existing virtual environment found in ./${VENV_DIR}.${NC}"
fi

VENV_PYTHON="${VENV_DIR}/bin/python"
if [ ! -f "$VENV_PYTHON" ]; then
    # Windows venv fallback
    VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
fi

# 4. Upgrade pip inside .venv
echo -e "${BLUE}[INFO] Upgrading pip inside virtual environment...${NC}"
"$VENV_PYTHON" -m pip install --upgrade pip --quiet || true

# 5. Install requirements.txt inside .venv
if [ -f "requirements.txt" ]; then
    echo -e "${BLUE}[INFO] Installing Python dependencies from requirements.txt...${NC}"
    "$VENV_PYTHON" -m pip install -r requirements.txt
    echo -e "${GREEN}[OK] Dependencies installed successfully.${NC}"
else
    echo -e "${RED}[ERROR] requirements.txt not found in project root!${NC}"
    exit 1
fi

# 6. Check System Dependencies (libpcap)
echo -e "${BLUE}[INFO] Checking system packet capture library (libpcap)...${NC}"
LIBPCAP_FOUND=false
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    LIBPCAP_FOUND=true
elif [ -f "/usr/include/pcap.h" ] || [ -f "/usr/lib/x86_64-linux-gnu/libpcap.so" ]; then
    LIBPCAP_FOUND=true
fi

if [ "$LIBPCAP_FOUND" = true ]; then
    echo -e "${GREEN}[OK] libpcap system library detected.${NC}"
else
    echo -e "${YELLOW}[WARNING] libpcap library was not detected.${NC}"
    echo -e "${YELLOW}For raw network packet capture via Scapy on Linux, install libpcap:${NC}"
    echo -e "          sudo apt update && sudo apt install -y libpcap-dev"
fi

# 7. Verify Python imports inside .venv
echo -e "${BLUE}[INFO] Verifying package imports in .venv...${NC}"
"$VENV_PYTHON" -c "
import yaml, scapy, fastapi, uvicorn, websockets
print('[OK] Verified core imports: PyYAML, Scapy, FastAPI, Uvicorn, WebSockets')
"

echo -e "${BLUE}====================================================${NC}"
echo -e "${GREEN} SETUP COMPLETE! Owl Monitor is ready to run.${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "You can now run the application directly with:"
echo -e "       ${GREEN}python3 main.py${NC}"
echo -e ""
echo -e "Note: To enable live network packet capture and iptables blocking:"
echo -e "       ${YELLOW}sudo python3 main.py${NC}"
echo -e "${BLUE}====================================================${NC}"

#!/bin/bash

# ============================================================
# SNORT SOC GUI LAUNCHER
# ============================================================

set -u

# -----------------------------
# Configuration
# -----------------------------

PYTHON_FILE="/home/kali2026/Documents/snort_soc_gui.py"
RULES_FILE="/etc/snort/rules/local.rules"
SNORT_CONFIG="/etc/snort/snort.lua"

# -----------------------------
# Colors
# -----------------------------

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

# -----------------------------
# Banner
# -----------------------------

clear

echo -e "${CYAN}"
echo "============================================================"
echo "              SNORT SOC GUI LAUNCHER"
echo "============================================================"
echo -e "${RESET}"

echo -e "${CYAN}[*] Starting Snort SOC environment...${RESET}"
echo

# ============================================================
# CHECK ROOT
# ============================================================

if [ "$EUID" -ne 0 ]; then

    echo -e "${YELLOW}[!] Root privileges are required.${RESET}"
    echo -e "${CYAN}[*] Restarting launcher with sudo...${RESET}"
    echo

    exec sudo "$0" "$@"

fi

echo -e "${GREEN}[OK] Running with root privileges.${RESET}"

# ============================================================
# CHECK PYTHON
# ============================================================

echo
echo "[*] Checking Python 3..."

if ! command -v python3 >/dev/null 2>&1; then

    echo -e "${RED}[ERROR] Python 3 is not installed.${RESET}"
    echo
    echo "Install it using:"
    echo
    echo "sudo apt update"
    echo "sudo apt install python3 python3-tk -y"
    echo

    exit 1

fi

PYTHON_VERSION=$(python3 --version)

echo -e "${GREEN}[OK] $PYTHON_VERSION${RESET}"

# ============================================================
# CHECK TKINTER
# ============================================================

echo
echo "[*] Checking Tkinter..."

if ! python3 -c "import tkinter" >/dev/null 2>&1; then

    echo -e "${RED}[ERROR] Tkinter is not installed.${RESET}"
    echo
    echo "Install it using:"
    echo
    echo "sudo apt install python3-tk -y"
    echo

    exit 1

fi

echo -e "${GREEN}[OK] Tkinter available.${RESET}"

# ============================================================
# CHECK SNORT
# ============================================================

echo
echo "[*] Checking Snort..."

if ! command -v snort >/dev/null 2>&1; then

    echo -e "${RED}[ERROR] Snort is not installed or not in PATH.${RESET}"
    echo
    echo "Check using:"
    echo
    echo "snort -V"
    echo

    exit 1

fi

SNORT_VERSION=$(snort -V 2>&1 | head -n 5)

echo -e "${GREEN}[OK] Snort detected.${RESET}"

echo
echo "$SNORT_VERSION"

# ============================================================
# CHECK PYTHON GUI
# ============================================================

echo
echo "[*] Checking Python GUI..."

if [ ! -f "$PYTHON_FILE" ]; then

    echo -e "${RED}[ERROR] Python GUI file not found:${RESET}"
    echo
    echo "$PYTHON_FILE"
    echo

    exit 1

fi

echo -e "${GREEN}[OK] Python GUI found.${RESET}"

# ============================================================
# CHECK SNORT CONFIGURATION
# ============================================================

echo
echo "[*] Checking Snort configuration..."

if [ ! -f "$SNORT_CONFIG" ]; then

    echo -e "${RED}[ERROR] Snort configuration not found:${RESET}"
    echo
    echo "$SNORT_CONFIG"
    echo

    echo "Search for snort.lua using:"
    echo
    echo "sudo find /etc /usr -name snort.lua 2>/dev/null"
    echo

    exit 1

fi

echo -e "${GREEN}[OK] Snort configuration found.${RESET}"
echo "    $SNORT_CONFIG"

# ============================================================
# CREATE RULE DIRECTORY
# ============================================================

echo
echo "[*] Checking Snort rules directory..."

RULES_DIR=$(dirname "$RULES_FILE")

if [ ! -d "$RULES_DIR" ]; then

    echo -e "${YELLOW}[!] Rules directory does not exist.${RESET}"
    echo "[*] Creating: $RULES_DIR"

    mkdir -p "$RULES_DIR"

fi

echo -e "${GREEN}[OK] Rules directory available.${RESET}"

# ============================================================
# CREATE TEST RULE
# ============================================================

if [ ! -f "$RULES_FILE" ]; then

    echo
    echo -e "${YELLOW}[!] local.rules does not exist.${RESET}"
    echo "[*] Creating basic ICMP test rule..."

    cat > "$RULES_FILE" << 'EOF'
alert icmp any any -> any any (msg:"SOC GUI TEST - ICMP DETECTED"; sid:1000001; rev:1;)
EOF

    chmod 644 "$RULES_FILE"

    echo -e "${GREEN}[OK] Test rule created.${RESET}"

else

    echo -e "${GREEN}[OK] local.rules exists.${RESET}"

fi

# ============================================================
# DISPLAY RULE
# ============================================================

echo
echo "------------------------------------------------------------"
echo "Current Snort test rule:"
echo "------------------------------------------------------------"

cat "$RULES_FILE"

echo "------------------------------------------------------------"

# ============================================================
# PYTHON SYNTAX CHECK
# ============================================================

echo
echo "[*] Checking Python syntax..."

if ! python3 -m py_compile "$PYTHON_FILE"; then

    echo
    echo -e "${RED}[ERROR] Python syntax check failed.${RESET}"
    echo
    echo "Fix the Python file before starting the GUI."
    echo

    exit 1

fi

echo -e "${GREEN}[OK] Python syntax is valid.${RESET}"

# ============================================================
# TEST SNORT CONFIGURATION
# ============================================================

echo
echo "[*] Validating Snort configuration..."

snort -T \
    -c "$SNORT_CONFIG" \
    -R "$RULES_FILE" \
    >/tmp/snort_gui_test.log 2>&1

SNORT_TEST_RESULT=$?

if [ $SNORT_TEST_RESULT -ne 0 ]; then

    echo -e "${RED}[ERROR] Snort configuration test failed.${RESET}"
    echo
    echo "Last 30 lines of the Snort test:"
    echo "------------------------------------------------------------"

    tail -n 30 /tmp/snort_gui_test.log

    echo "------------------------------------------------------------"
    echo

    exit 1

fi

echo -e "${GREEN}[OK] Snort configuration is valid.${RESET}"

# ============================================================
# DETECT NETWORK INTERFACES
# ============================================================

echo
echo "[*] Detecting network interfaces..."

ip -br addr

echo

# ============================================================
# GUI INFORMATION
# ============================================================

echo "============================================================"
echo "                 LAUNCHING SNORT SOC GUI"
echo "============================================================"

echo
echo "Python GUI:"
echo "  $PYTHON_FILE"

echo
echo "Snort configuration:"
echo "  $SNORT_CONFIG"

echo
echo "Rules:"
echo "  $RULES_FILE"

echo
echo "============================================================"
echo

sleep 2

# ============================================================
# LAUNCH PYTHON GUI
# ============================================================

cd "$(dirname "$PYTHON_FILE")" || exit 1

echo -e "${GREEN}[*] Starting Python GUI...${RESET}"
echo

exec python3 "$PYTHON_FILE"

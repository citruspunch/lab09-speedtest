#!/bin/bash
#
# run_speedtest.sh: Automated execution script for Lab 09 Speedtest (Raw Sockets TCP)
#
# Steps:
#   1. Compiles client and server in C via make.
#   2. Installs a firewall rule to drop kernel RST packets on ephemeral ports.
#   3. Starts speedtest_server in the background.
#   4. Starts tcpdump capturing to speedtest.pcap.
#   5. Executes speedtest_client.
#   6. Displays captured packet count and restores firewall rules.
#
# Usage:
#   ./run_speedtest.sh [-p PORT] [-i INTERFACE] [--keep-server] [--skip-build]
#

set -u

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT_BIN="$PROJECT_DIR/build/speedtest_client"
SERVER_BIN="$PROJECT_DIR/build/speedtest_server"
PCAP_FILE="$PROJECT_DIR/speedtest.pcap"
LOG_FILE="$PROJECT_DIR/speedtest.log"
SERVER_LOG="$PROJECT_DIR/server.log"

PORT=5001
IFACE=""
KEEP_SERVER=0
SKIP_BUILD=0
OS="$(uname -s)"

# ANSI Color definitions
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_DIM="\033[2m"
CLR_CYAN="\033[36m"
CLR_GREEN="\033[32m"
CLR_YELLOW="\033[33m"
CLR_BLUE="\033[34m"
CLR_MAGENTA="\033[35m"

if [ "$OS" = "Darwin" ]; then
    IFACE="lo0"
else
    IFACE="lo"
fi

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port)
            shift; PORT="${1:-5001}" ;;
        -i|--interface)
            shift; IFACE="${1:-lo0}" ;;
        --keep-server)
            KEEP_SERVER=1 ;;
        --skip-build)
            SKIP_BUILD=1 ;;
        -h|--help)
            echo "Usage: $0 [-p PORT] [-i INTERFACE] [--keep-server] [--skip-build]"
            exit 0 ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

SERVER_PID=""
TCPDUMP_PID=""
PF_WAS_ENABLED="unknown"
FIREWALL_CHANGED=0

cleanup() {
    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        echo -e "${CLR_YELLOW}[cleanup] Stopping tcpdump (PID $TCPDUMP_PID)...${CLR_RESET}"
        sudo kill "$TCPDUMP_PID" 2>/dev/null || true
        sleep 1
    fi

    if [ "$FIREWALL_CHANGED" = "1" ]; then
        if [ "$OS" = "Darwin" ]; then
            echo -e "${CLR_YELLOW}[cleanup] Restoring pf configuration (/etc/pf.conf)...${CLR_RESET}"
            sudo pfctl -f /etc/pf.conf 2>&1 | head -n 5 || true
            if [ "$PF_WAS_ENABLED" = "disabled" ]; then
                sudo pfctl -d 2>&1 || true
            fi
        else
            echo -e "${CLR_YELLOW}[cleanup] Removing iptables rule...${CLR_RESET}"
            sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP 2>/dev/null || true
        fi
    fi

    if [ "$KEEP_SERVER" = "0" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo -e "${CLR_YELLOW}[cleanup] Stopping speedtest_server (PID $SERVER_PID)...${CLR_RESET}"
        kill "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo -e "${CLR_CYAN}${CLR_BOLD}======================================================================${CLR_RESET}"
echo -e "${CLR_CYAN}${CLR_BOLD}          LAB 09: SPEEDTEST (RAW SOCKETS TCP BENCHMARK)               ${CLR_RESET}"
echo -e "${CLR_CYAN}${CLR_BOLD}======================================================================${CLR_RESET}"
echo -e "${CLR_DIM}OS:               ${CLR_RESET}$OS"
echo -e "${CLR_DIM}Target Interface: ${CLR_RESET}$IFACE"
echo -e "${CLR_DIM}Server Port:      ${CLR_RESET}$PORT"
echo -e "${CLR_DIM}Project Dir:      ${CLR_RESET}$PROJECT_DIR"
echo ""

sudo -v || { echo "Error: sudo credentials required for raw sockets" >&2; exit 1; }

# 1. Build
if [ "$SKIP_BUILD" = "0" ]; then
    echo -e "${CLR_GREEN}${CLR_BOLD}[1/5] Compiling C client and server with make${CLR_RESET}"
    make -C "$PROJECT_DIR" clean
    make -C "$PROJECT_DIR" || { echo "Compilation failed." >&2; exit 1; }
fi

# 2. Configure firewall to drop kernel RST packets
echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}[2/5] Configuring firewall to block kernel RST packets${CLR_RESET}"
if [ "$OS" = "Darwin" ]; then
    if sudo pfctl -s info 2>/dev/null | grep -qi "Status:.*Enabled"; then
        PF_WAS_ENABLED="enabled"
    else
        PF_WAS_ENABLED="disabled"
    fi
    echo -e "${CLR_DIM}[run_speedtest] Initial pf status: $PF_WAS_ENABLED${CLR_RESET}"
    echo 'block drop out proto tcp from any port 40000:49999 flags R/R' | sudo pfctl -f - 2>&1
    sudo pfctl -e 2>&1 || true
    FIREWALL_CHANGED=1
else
    echo -e "${CLR_DIM}[run_speedtest] Adding iptables rule for ports 40000:49999${CLR_RESET}"
    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP 2>/dev/null || true
    FIREWALL_CHANGED=1
fi

# 3. Launch server
echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}[3/5] Starting speedtest_server in background${CLR_RESET}"
pkill -f "speedtest_server" 2>/dev/null || true
sleep 0.5
"$SERVER_BIN" -p "$PORT" -b 127.0.0.1 > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo -e "${CLR_DIM}[run_speedtest] speedtest_server PID=$SERVER_PID, log=$SERVER_LOG${CLR_RESET}"

READY=0
for i in $(seq 1 20); do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then READY=1; break; fi
    sleep 0.2
done
if [ "$READY" = "0" ]; then
    echo "Error: Server failed to start on port $PORT" >&2
    cat "$SERVER_LOG"
    exit 1
fi

# 4. Start packet capture
echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}[4/5] Starting tcpdump on $IFACE${CLR_RESET}"
rm -f "$PCAP_FILE" "$LOG_FILE"
sudo tcpdump -i "$IFACE" -w "$PCAP_FILE" tcp port "$PORT" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.8
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    echo "Error: tcpdump failed to start on $IFACE" >&2
    exit 1
fi
echo -e "${CLR_DIM}[run_speedtest] tcpdump PID=$TCPDUMP_PID writing to $PCAP_FILE${CLR_RESET}"

# 5. Run client
echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}[5/5] Running speedtest_client${CLR_RESET}"
set +u
sudo "$CLIENT_BIN" -l 127.0.0.1 -s 127.0.0.1 -p "$PORT" -f "$PROJECT_DIR/assets/1kb-image" -i "$IFACE" 2>&1 | tee "$LOG_FILE"
CLIENT_EXIT=${PIPESTATUS[0]:-0}
set -u

sleep 1
if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    sudo kill "$TCPDUMP_PID" 2>/dev/null || true
    sleep 1
    TCPDUMP_PID=""
fi

echo ""
echo -e "${CLR_CYAN}${CLR_BOLD}======================================================================${CLR_RESET}"
echo -e "${CLR_CYAN}${CLR_BOLD}                  TCPDUMP PACKET FLOW ANALYSIS                        ${CLR_RESET}"
echo -e "${CLR_CYAN}${CLR_BOLD}======================================================================${CLR_RESET}"
if [ -f "$PCAP_FILE" ]; then
    echo -e "${CLR_DIM}Capture File: ${CLR_RESET}$PCAP_FILE ($(wc -c < "$PCAP_FILE" | tr -d ' ') bytes)"
    echo -e "${CLR_DIM}Total packets captured: ${CLR_RESET}${CLR_BOLD}$(tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | wc -l | tr -d ' ')${CLR_RESET}"
    echo ""
    echo -e "${CLR_YELLOW}First 25 packets:${CLR_RESET}"
    tcpdump -nn -r "$PCAP_FILE" 2>&1 | head -n 25
    echo "..."
    echo -e "${CLR_YELLOW}Last 10 packets:${CLR_RESET}"
    tcpdump -nn -r "$PCAP_FILE" 2>&1 | tail -n 10
else
    echo "Warning: $PCAP_FILE was not created"
fi

echo ""
echo -e "${CLR_CYAN}${CLR_BOLD}======================================================================${CLR_RESET}"
echo -e "${CLR_CYAN}${CLR_BOLD}Server log summary ($SERVER_LOG):${CLR_RESET}"
cat "$SERVER_LOG"
echo -e "${CLR_CYAN}${CLR_BOLD}======================================================================${CLR_RESET}"

exit "$CLIENT_EXIT"

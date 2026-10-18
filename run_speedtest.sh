#!/bin/bash
#
# run_speedtest.sh — Automated execution of Lab 09: SpeedTest (Raw Sockets TCP)
#
# Automates the entire workflow:
#   1. Compiles client and server in C (make).
#   2. Configures firewall rule to block kernel RST packets on ephemeral ports.
#   3. Launches the speedtest C server in background.
#   4. Starts tcpdump background capture to 'speedtest.pcap'.
#   5. Executes the raw socket speedtest client (Stage 1 Latency, Stage 2 TCP Upload).
#   6. Displays tcpdump packet analysis and restores firewall rules.
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

# Detect default loopback interface
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
    # Stop tcpdump
    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        echo "[cleanup] Stopping tcpdump ($TCPDUMP_PID)..."
        sudo kill "$TCPDUMP_PID" 2>/dev/null || true
        sleep 1
    fi

    # Restore firewall
    if [ "$FIREWALL_CHANGED" = "1" ]; then
        if [ "$OS" = "Darwin" ]; then
            echo "[cleanup] Restoring macOS pf firewall (/etc/pf.conf)..."
            sudo pfctl -f /etc/pf.conf 2>&1 | head -n 5 || true
            if [ "$PF_WAS_ENABLED" = "disabled" ]; then
                sudo pfctl -d 2>&1 || true
            fi
        else
            echo "[cleanup] Restoring Linux iptables rule..."
            sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP 2>/dev/null || true
        fi
    fi

    # Stop server unless requested to keep alive
    if [ "$KEEP_SERVER" = "0" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "[cleanup] Stopping speedtest_server ($SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "======================================================================"
echo "          LAB 09: SPEEDTEST (RAW SOCKETS TCP BENCHMARK)               "
echo "======================================================================"
echo "OS:               $OS"
echo "Target Interface: $IFACE"
echo "Server Port:      $PORT"
echo "Project Dir:      $PROJECT_DIR"
echo ""

# Validate sudo upfront
sudo -v || { echo "Error: sudo credentials required for raw sockets/packet capture" >&2; exit 1; }

# 1. Build
if [ "$SKIP_BUILD" = "0" ]; then
    echo "── [1/5] Compiling C client and server with make ──"
    make -C "$PROJECT_DIR" clean
    make -C "$PROJECT_DIR" || { echo "Compilation failed!" >&2; exit 1; }
fi

# 2. Check & Configure Firewall to suppress OS kernel RST
echo ""
echo "── [2/5] Configuring firewall to prevent OS kernel RST ──"
if [ "$OS" = "Darwin" ]; then
    if sudo pfctl -s info 2>/dev/null | grep -qi "Status:.*Enabled"; then
        PF_WAS_ENABLED="enabled"
    else
        PF_WAS_ENABLED="disabled"
    fi
    echo "[run_speedtest] pf initial status: $PF_WAS_ENABLED"
    echo "[run_speedtest] Applying temporary rule: block drop out proto tcp from any port 40000:49999 flags R/R"
    echo 'block drop out proto tcp from any port 40000:49999 flags R/R' | sudo pfctl -f - 2>&1
    sudo pfctl -e 2>&1 || true
    FIREWALL_CHANGED=1
else
    echo "[run_speedtest] Adding iptables rule: DROP RST packets from port 40000:49999"
    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP 2>/dev/null || true
    FIREWALL_CHANGED=1
fi

# 3. Launch Speedtest Server
echo ""
echo "── [3/5] Starting speedtest_server in background ──"
pkill -f "speedtest_server" 2>/dev/null || true
sleep 0.5
"$SERVER_BIN" -p "$PORT" -b 127.0.0.1 > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo "[run_speedtest] speedtest_server PID=$SERVER_PID, log=$SERVER_LOG"

# Wait until listening
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

# 4. Start tcpdump
echo ""
echo "── [4/5] Starting tcpdump capture on $IFACE ──"
rm -f "$PCAP_FILE" "$LOG_FILE"
sudo tcpdump -i "$IFACE" -w "$PCAP_FILE" tcp port "$PORT" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.8
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    echo "Error: tcpdump failed to start on interface $IFACE" >&2
    exit 1
fi
echo "[run_speedtest] tcpdump active (PID=$TCPDUMP_PID) capturing to $PCAP_FILE"

# 5. Execute Speedtest Raw Socket Client
echo ""
echo "── [5/5] Executing RAW socket speedtest_client ──"
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
echo "======================================================================"
echo "                  TCPDUMP PACKET FLOW ANALYSIS                        "
echo "======================================================================"
if [ -f "$PCAP_FILE" ]; then
    echo "Capture File: $PCAP_FILE ($(wc -c < "$PCAP_FILE" | tr -d ' ') bytes)"
    echo "Total packets captured: $(tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | wc -l | tr -d ' ')"
    echo ""
    echo "First 25 packets:"
    tcpdump -nn -r "$PCAP_FILE" 2>&1 | head -n 25
    echo "..."
    echo "Last 10 packets (Connection close):"
    tcpdump -nn -r "$PCAP_FILE" 2>&1 | tail -n 10
else
    echo "Warning: $PCAP_FILE was not generated"
fi

echo ""
echo "======================================================================"
echo "Server log summary ($SERVER_LOG):"
cat "$SERVER_LOG"
echo "======================================================================"

exit "$CLIENT_EXIT"

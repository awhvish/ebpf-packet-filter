#!/bin/bash
# L4 Load Balancer Test Script
# Run as root: sudo ./benchmark.sh

set -e

PORT=8080

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "  XDP Load Balancer Test"
echo "=============================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo ./benchmark.sh${NC}"
    exit 1
fi

# Check if LB binary exists
if [ ! -f "./lb" ]; then
    echo -e "${YELLOW}Building load balancer...${NC}"
    go generate && go build -o lb
fi

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    pkill -f "./lb" 2>/dev/null || true
    ip link set dev lo xdp off 2>/dev/null || true
}
trap cleanup EXIT

echo -e "${GREEN}[1/3] Starting Load Balancer${NC}"
echo "----------------------------"

# Start LB in background with auto-input
(echo "$PORT"; sleep 1; echo "add 127.0.0.1"; sleep 1; echo "list") | timeout 30 ./lb lo &
LB_PID=$!
sleep 3

echo ""
echo -e "${GREEN}[2/3] Sending Test Traffic${NC}"
echo "---------------------------"
echo "Sending 100 TCP SYN packets from different source ports..."

# Send traffic from different source ports to test consistent hashing
for i in {1..100}; do
    # Use different source ports to see hash distribution
    timeout 0.1 bash -c "echo test | nc -w1 -p $((10000 + i)) 127.0.0.1 $PORT" 2>/dev/null || true
done

echo "Done sending packets."

echo ""
echo -e "${GREEN}[3/3] Checking Results${NC}"
echo "----------------------"

# Read trace pipe for LB logs
echo "Kernel logs (last 10 LB entries):"
cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | head -10 &
TRACE_PID=$!
sleep 2
kill $TRACE_PID 2>/dev/null || true

echo ""
echo "=============================================="
echo "  Test Complete"
echo "=============================================="
echo ""
echo "The load balancer stats should have printed above."
echo "Check connection distribution across backends."

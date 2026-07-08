#!/bin/bash

# Sphinx Protocol Launcher
# Usage: ./run.sh [single|device|cluster|help]
#
# single      — one node on localhost (development only)
# device      — auto-detect IP and run a real-device node (with optional --seeds)
# cluster     — launch N nodes on localhost in separate terminal windows (default: 3)
# help        — show this message

set -e

# Get the absolute path to the script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Launch command in a new terminal window
launch_terminal() {
    local cmd="$1"
    local full_cmd="cd \"$SCRIPT_DIR\" && $cmd"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS – use osascript with proper escaping
        local escaped_cmd="${full_cmd//\"/\\\"}"   # escape double quotes
        osascript -e "tell app \"Terminal\" to do script \"$escaped_cmd\""
    elif command -v gnome-terminal &> /dev/null; then
        gnome-terminal -- bash -c "$full_cmd; exec bash"
    elif command -v xterm &> /dev/null; then
        xterm -e bash -c "$full_cmd; exec bash"
    else
        return 1
    fi
    return 0
}

# Detect local IP (macOS fallback to Linux)
detect_ip() {
    if command -v ipconfig &> /dev/null; then
        LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "")
    fi
    if [ -z "$LOCAL_IP" ]; then
        if command -v hostname &> /dev/null; then
            LOCAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "")
        fi
    fi
    echo "$LOCAL_IP"
}

# Default mode
MODE=${1:-"help"}

# === device mode ===
if [ "$MODE" == "device" ]; then
    shift  # remove the 'device' argument

    # Default values for device mode
    ROLE="validator"
    TCP_PORT="30303"
    UDP_PORT="30304"
    HTTP_PORT="8545"
    DATADIR="data/validator"
    PBFT=""
    SEEDS=""
    NETWORK="devnet"
    MODE_FLAG="development"

    # Parse arguments (supports both --flag=value and --flag value)
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role=*)
                ROLE="${1#*=}"
                shift
                ;;
            --role)
                ROLE="$2"
                shift 2
                ;;
            --tcp-port=*)
                TCP_PORT="${1#*=}"
                shift
                ;;
            --tcp-port)
                TCP_PORT="$2"
                shift 2
                ;;
            --udp-port=*)
                UDP_PORT="${1#*=}"
                shift
                ;;
            --udp-port)
                UDP_PORT="$2"
                shift 2
                ;;
            --http-port=*)
                HTTP_PORT="${1#*=}"
                shift
                ;;
            --http-port)
                HTTP_PORT="$2"
                shift 2
                ;;
            --datadir=*)
                DATADIR="${1#*=}"
                shift
                ;;
            --datadir)
                DATADIR="$2"
                shift 2
                ;;
            --seeds=*)
                SEEDS="${1#*=}"
                shift
                ;;
            --seeds)
                SEEDS="$2"
                shift 2
                ;;
            --pbft)
                PBFT="--pbft"
                shift
                ;;
            --network=*)
                NETWORK="${1#*=}"
                shift
                ;;
            --network)
                NETWORK="$2"
                shift 2
                ;;
            --mode=*)
                MODE_FLAG="${1#*=}"
                shift
                ;;
            --mode)
                MODE_FLAG="$2"
                shift 2
                ;;
            *)
                echo "Unknown option for device mode: $1"
                exit 1
                ;;
        esac
    done

    # Detect IP
    LOCAL_IP=$(detect_ip)
    if [ -z "$LOCAL_IP" ]; then
        echo "❌ Could not detect your local IP. Please set it manually with --tcp-addr."
        exit 1
    fi

    echo "🔍 Detected local IP: $LOCAL_IP"

    # Build the command
    CMD="go run main.go node --role=$ROLE --tcp-addr=$LOCAL_IP:$TCP_PORT --udp-port=$UDP_PORT --http-port=127.0.0.1:$HTTP_PORT --datadir=$DATADIR $PBFT --mode=$MODE_FLAG --network=$NETWORK"

    if [ -n "$SEEDS" ]; then
        CMD="$CMD --seeds=$SEEDS"
    fi

    echo "🚀 Running: $CMD"
    exec $CMD
fi

# === cluster mode ===
if [ "$MODE" == "cluster" ]; then
    shift
    N=${1:-3}                     # default 3 nodes
    BASE_TCP=32307
    BASE_UDP=32308
    BASE_HTTP=8545
    SEED_ADDR="127.0.0.1:${BASE_TCP}"

    echo "🚀 Launching $N-node cluster in separate terminal windows..."
    echo ""

    for i in $(seq 0 $((N-1))); do
        TCP=$((BASE_TCP + i))
        UDP=$((BASE_UDP + i))
        HTTP=$((BASE_HTTP + i))
        DATA="data${i}"
        CMD="go run main.go node --role=validator --tcp-addr=127.0.0.1:${TCP} --udp-port=${UDP} --http-port=127.0.0.1:${HTTP} --datadir=${DATA} --nodes=${N} --node-index=${i} --pbft"
        [ $i -ne 0 ] && CMD="${CMD} --seeds=${SEED_ADDR}"

        echo "Node $i: TCP $TCP, UDP $UDP, HTTP $HTTP"
        if ! launch_terminal "$CMD"; then
            # Fallback: background with logs
            mkdir -p logs
            echo "  (fallback: logging to logs/node${i}.log)"
            $CMD > "logs/node${i}.log" 2>&1 &
        fi
        sleep 0.5  # small delay to avoid overwhelming the system
    done

    echo ""
    if [[ "$OSTYPE" != "darwin"* ]] && ! command -v gnome-terminal &> /dev/null && ! command -v xterm &> /dev/null; then
        echo "✅ All nodes started in the background. Logs are in logs/node*.log"
        echo "📊 Monitor: tail -f logs/node0.log"
        echo "🛑 To stop: pkill -f 'go run main.go node'"
    else
        echo "✅ All nodes launched in separate terminal windows."
        echo "🛑 To stop: Close each terminal window, or run pkill -f 'go run main.go node'"
    fi
    exit 0
fi

# === single mode ===
if [ "$MODE" == "single" ]; then
    echo "Starting SINGLE NODE mode (same-box 3-validator devnet)..."
    # Clean stale state directories
    rm -rf ./data/node0
    rm -rf "./data/Node-127.0.0.1:32307" "./data/Node-127.0.0.1:32308" "./data/Node-127.0.0.1:32309"
    go run ./main.go node \
        --role=validator \
        --tcp-addr=127.0.0.1:32307 \
        --udp-port=32308 \
        --http-port=127.0.0.1:8545 \
        --datadir=./data/node0 \
        --mode=development \
        --network=devnet \
        --nodes=3 --node-index=0 \
        --pbft
    exit 0
fi

# === help or unknown ===
if [ "$MODE" == "help" ] || [ "$MODE" == "--help" ] || [ "$MODE" == "-h" ]; then
    cat <<EOF
Usage: ./run.sh [single|device|cluster|help]

  single      — one node on localhost (development only)
  device      — auto-detect IP and run a real-device node
                Additional flags for device mode:
                  --tcp-port <port>   (default: 30303)
                  --udp-port <port>   (default: 30304)
                  --http-port <port>  (default: 8545)
                  --datadir <dir>     (default: data/validator)
                  --seeds <addr>      comma-separated seed addresses
                  --pbft              enable PBFT consensus
                  --network <net>     (default: devnet)
                  --mode <mode>       (default: development)
  cluster     — launch N nodes on localhost in separate terminal windows (default: 3)
                Usage: ./run.sh cluster [N]
  help        — show this message

Examples:
  ./run.sh device --pbft
  ./run.sh device --seeds=192.168.1.5:30303 --pbft --tcp-port=30304
  ./run.sh single
  ./run.sh cluster 6
EOF
    exit 0
else
    echo "Unknown mode: $MODE"
    echo "Usage: ./run.sh [single|device|cluster|help]"
    exit 1
fi
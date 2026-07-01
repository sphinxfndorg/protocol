#!/bin/bash

# Sphinx Protocol Launcher
# Usage: ./run.sh [single|device|help]
#
# single      — one node on localhost (development only)
# device      — auto-detect IP and run a real-device node (with optional --seeds)
# help        — show this message

set -e

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

# === single mode ===
if [ "$MODE" == "single" ]; then
    echo "Starting SINGLE NODE mode (same-box 3-validator devnet)..."
    # NOTE: the node process stores LevelDB under data/Node-<tcp-addr>/,
    # not directly under --datadir — clean all three so stale state from a
    # previous run can't leave a locked/mismatched genesis behind.
    rm -rf ./data/node0
    rm -rf "./data/Node-127.0.0.1:32307" "./data/Node-127.0.0.1:32308" "./data/Node-127.0.0.1:32309"
    go run ./src/cli/main.go node \
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
    echo "Usage: ./run.sh [single|device|help]"
    echo ""
    echo "  single      — one node on localhost (development only)"
    echo "  device      — auto-detect IP and run a real-device node"
    echo "                Additional flags for device mode:"
    echo "                  --tcp-port <port>   (default: 30303)"
    echo "                  --udp-port <port>   (default: 30304)"
    echo "                  --http-port <port>  (default: 8545)"
    echo "                  --datadir <dir>     (default: data/validator)"
    echo "                  --seeds <addr>      comma-separated seed addresses"
    echo "                  --pbft              enable PBFT consensus"
    echo "                  --network <net>     (default: devnet)"
    echo "                  --mode <mode>       (default: development)"
    echo "  help        — show this message"
    echo ""
    echo "Examples:"
    echo "  ./run.sh device --pbft"
    echo "  ./run.sh device --seeds=192.168.1.5:30303 --pbft --tcp-port=30304"
    echo "  ./run.sh single"
    exit 0
else
    echo "Unknown mode: $MODE"
    echo "Usage: ./run.sh [single|device|help]"
    exit 1
fi
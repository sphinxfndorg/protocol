#!/bin/bash

# Sphinx Protocol Launcher
# Usage: ./launch.sh [single|cluster]

MODE=${1:-"cluster"}

if [ "$MODE" == "single" ]; then
    echo "Starting SINGLE NODE mode..."
    rm -rf ./data/node0
    go run ./src/cli/main.go node \
        --node-index=0 \
        --nodes=1 \
        --role=validator \
        --tcp-addr=127.0.0.1:30307 \
        --udp-port=30308 \
        --http-port=127.0.0.1:8545 \
        --datadir=./data/node0 \
        --mode=development \
        --network=devnet
else
    echo "Starting 3-NODE PBFT CLUSTER..."
    echo "Opening 3 terminal windows..."
    
    # Open Terminal 1 (Node 0) - Genesis node
    osascript -e 'tell application "Terminal"
        activate
        do script "cd ~/desktop/protocol && rm -rf ./data/node0 && go run ./src/cli/main.go node --node-index=0 --nodes=3 --role=validator --tcp-addr=127.0.0.1:30307 --udp-port=30308 --http-port=127.0.0.1:8545 --datadir=./data/node0 --pbft --mode=development --network=devnet"
    end tell'
    
    sleep 2
    
    # Open Terminal 2 (Node 1)
    osascript -e 'tell application "Terminal"
        activate
        do script "cd ~/desktop/protocol && rm -rf ./data/node1 && go run ./src/cli/main.go node --node-index=1 --nodes=3 --role=validator --tcp-addr=127.0.0.1:30309 --udp-port=30310 --http-port=127.0.0.1:8546 --datadir=./data/node1 --pbft --mode=development --network=devnet"
    end tell'
    
    sleep 2
    
    # Open Terminal 3 (Node 2)
    osascript -e 'tell application "Terminal"
        activate
        do script "cd ~/desktop/protocol && rm -rf ./data/node2 && go run ./src/cli/main.go node --node-index=2 --nodes=3 --role=validator --tcp-addr=127.0.0.1:30311 --udp-port=30312 --http-port=127.0.0.1:8547 --datadir=./data/node2 --pbft --mode=development --network=devnet"
    end tell'
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "✅ 3 terminals opened with PBFT nodes (DEVNET)"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "Port Mapping:"
    echo "  Node 0: TCP 30307 | UDP 30308 | HTTP 8545"
    echo "  Node 1: TCP 30309 | UDP 30310 | HTTP 8546"
    echo "  Node 2: TCP 30311 | UDP 30312 | HTTP 8547"
    echo ""
    echo "Monitor Node 0:"
    echo "  tail -f ./logs/node0.log"
    echo ""
    echo "Check block height:"
    echo "  curl http://127.0.0.1:8545/blockcount"
    echo "  curl http://127.0.0.1:8546/blockcount"
    echo "  curl http://127.0.0.1:8547/blockcount"
    echo ""
    echo "Stop all nodes:"
    echo "  pkill -f 'main.go'"
fi
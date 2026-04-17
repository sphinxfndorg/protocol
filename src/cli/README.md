# ============================================
# LOCAL DEVELOPMENT CLUSTER (3 nodes on one machine)
# ============================================

# Terminal Window 1 - Node 0 (Genesis Node)
cd ~/desktop/protocol
rm -rf ./data/node0
go run ./src/cli/main.go node \
    --node-index=0 \
    --nodes=3 \
    --role=validator \
    --tcp-addr=127.0.0.1:32307 \
    --udp-port=32308 \
    --http-port=127.0.0.1:8545 \
    --datadir=./data/node0 \
    --pbft \
    --mode=development

# Terminal Window 2 - Node 1
cd ~/desktop/protocol
rm -rf ./data/node1
go run ./src/cli/main.go node \
    --node-index=1 \
    --nodes=3 \
    --role=validator \
    --tcp-addr=127.0.0.1:32308 \
    --udp-port=32309 \
    --http-port=127.0.0.1:8546 \
    --datadir=./data/node1 \
    --pbft \
    --mode=development

# Terminal Window 3 - Node 2
cd ~/desktop/protocol
rm -rf ./data/node2
go run ./src/cli/main.go node \
    --node-index=2 \
    --nodes=3 \
    --role=validator \
    --tcp-addr=127.0.0.1:32309 \
    --udp-port=32310 \
    --http-port=127.0.0.1:8547 \
    --datadir=./data/node2 \
    --pbft \
    --mode=development


# ============================================
# Make and Run Launch Script
# ============================================


```
# Navigate to CLI directory
cd ~/desktop/protocol/src/cli
```

```
# Make the script executable
chmod +x launch.sh
```

```
# Run the cluster (3 nodes)
./launch.sh cluster
```

```
# Or run single node mode
./launch.sh single
```
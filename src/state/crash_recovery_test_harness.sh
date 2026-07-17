#!/usr/bin/env bash
# ============================================================================
# Crash-Recovery ("kill -9") Test Harness
#
# Validates that a node recovering from an abrupt kill produces a consistent
# block index across rawdb (LevelDB) and JSON-on-disk stores.
#
# Usage:
#   ./crash_recovery_test_harness.sh [node_data_dir] [num_blocks] [num_crashes]
#
# Defaults:
#   node_data_dir = ./data/node1  (the default devnet node 1 directory)
#   num_blocks    = 100            (write this many blocks, killing at random)
#   num_crashes   = 3              (number of random crashes to simulate)
#
# The script:
#   1. Starts a node (or reuses an existing one)
#   2. Waits for the node to be producing blocks
#   3. Sends N blocks worth of load, then kills the process with SIGKILL
#   4. Restarts the node
#   5. Verifies rawdb and JSON indices agree on restart
#   6. Repeats for num_crashes iterations
#   7. Runs a final consistency check
#
# Exit codes:
#   0 - all consistency checks passed
#   1 - a consistency check failed (divergence detected)
#   2 - a setup/teardown error occurred
# ============================================================================
set -euo pipefail

# ---- Configuration ---------------------------------------------------------
NODE_DIR="${1:-./data/node1}"
NUM_BLOCKS="${2:-100}"
NUM_CRASHES="${3:-3}"
NODE_BINARY="${4:-./build/protocold}"  # adjust to your binary path
NODE_ID="Node-127.0.0.1:30303"         # default node1 ID

PROTOCOL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CHECK_SCRIPT="$(dirname "$0")/check_consistency.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_cnt=0
fail_cnt=0

# ---- Helper functions ------------------------------------------------------

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# find_pid returns the PID of the running protocol node, or empty string.
find_pid() {
    pgrep -f "${NODE_BINARY}" 2>/dev/null || true
}

# wait_for_blocks waits until the node has produced at least N blocks.
wait_for_blocks() {
    local target=$1
    local timeout_sec=60
    local waited=0
    while [ $waited -lt $timeout_sec ]; do
        local cur
        cur=$(find_block_height) || echo "0"
        if [ "$cur" -ge "$target" ] 2>/dev/null; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    log_error "Timed out waiting for block height >= ${target}"
    return 1
}

# find_block_height reads the chain_state.json to get current block height.
find_block_height() {
    local state_file="${NODE_DIR}/${NODE_ID}/blockchain/state/chain_state.json"
    if [ ! -f "$state_file" ]; then
        echo "0"
        return
    fi
    # Use grep/sed to extract totalBlocks without requiring jq
    local total
    total=$(grep -o '"totalBlocks":[[:space:]]*[0-9]*' "$state_file" 2>/dev/null | grep -o '[0-9]*$' || echo "0")
    echo "$total"
}

# ---------------------------------------------------------------------------
# Phase 0: Check environment
# ---------------------------------------------------------------------------
log_info "=== Crash-Recovery Test Harness ==="
log_info "Node dir:     ${NODE_DIR}"
log_info "Num blocks:   ${NUM_BLOCKS}"
log_info "Num crashes:  ${NUM_CRASHES}"
echo ""

# Ensure the node binary exists
if [ ! -f "$NODE_BINARY" ] && [ ! -x "$(command -v "${NODE_BINARY}")" ]; then
    # Try to find it in the build directory
    if [ -f "${PROTOCOL_DIR}/build/protocold" ]; then
        NODE_BINARY="${PROTOCOL_DIR}/build/protocold"
    elif [ -f "${PROTOCOL_DIR}/protocold" ]; then
        NODE_BINARY="${PROTOCOL_DIR}/protocold"
    else
        log_warn "Node binary not found at ${NODE_BINARY}"
        log_warn "Will run in verification-only mode (assume node is already running)"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 1: Ensure node is running
# ---------------------------------------------------------------------------
PID=$(find_pid)
if [ -z "$PID" ]; then
    if [ -f "$NODE_BINARY" ]; then
        log_info "Starting node: ${NODE_BINARY} --data-dir ${NODE_DIR} &"
        # Use a config or command line appropriate for your node
        ${NODE_BINARY} --data-dir "${NODE_DIR}" > /tmp/protocol-node.log 2>&1 &
        sleep 5
        PID=$(find_pid)
        if [ -z "$PID" ]; then
            log_error "Failed to start node. Check /tmp/protocol-node.log"
            exit 2
        fi
        log_info "Node started with PID ${PID}"
    else
        log_error "No node binary found and no node is running. Install the binary or start one manually."
        exit 2
    fi
else
    log_info "Node already running with PID ${PID}"
fi

# Record initial block height
INITIAL_HEIGHT=$(find_block_height)
log_info "Initial block height: ${INITIAL_HEIGHT}"

# ---------------------------------------------------------------------------
# Phase 2: Crash-recovery loop
# ---------------------------------------------------------------------------
for crash_iter in $(seq 1 "${NUM_CRASHES}"); do
    echo ""
    log_info "=== Crash iteration ${crash_iter} / ${NUM_CRASHES} ==="

    # Send some blocks' worth of load (or just wait for the node to produce them)
    TARGET_HEIGHT=$((INITIAL_HEIGHT + (crash_iter * NUM_BLOCKS / NUM_CRASHES)))
    log_info "Waiting for block height >= ${TARGET_HEIGHT} ..."
    wait_for_blocks "${TARGET_HEIGHT}" || true

    HEIGHT_BEFORE=$(find_block_height)
    log_info "Height before kill: ${HEIGHT_BEFORE}"

    # === KILL -9 ===
    PID=$(find_pid)
    if [ -n "$PID" ]; then
        log_warn "Killing node PID ${PID} with SIGKILL ..."
        kill -9 "$PID" 2>/dev/null || true
        sleep 2  # give OS time to release resources

        # Verify it's dead
        if kill -0 "$PID" 2>/dev/null; then
            log_error "Process ${PID} still alive after SIGKILL!"
            exit 2
        fi
        log_info "Node killed."
    fi

    # ---------------------------------------------------------------------------
    # Phase 3: Consistency check on the crashed state
    # ---------------------------------------------------------------------------
    log_info "Running consistency check on crashed state ..."

    # We run a Go test that loads the storage and verifies rawdb <-> JSON agreement.
    # This test must be in the state package and have access to the LevelDB + JSON files.
    if [ -f "$CHECK_SCRIPT" ]; then
        bash "$CHECK_SCRIPT" "${NODE_DIR}" "${NODE_ID}" || {
            log_error "Consistency check FAILED after crash ${crash_iter}"
            fail_cnt=$((fail_cnt + 1))
        }
    else
        # Inline check: use Go test
        log_info "Running in-process consistency check via Go test..."
        # Run a dedicated consistency check test that reads the node's data dir
        cd "${PROTOCOL_DIR}" && go test ./src/state/ -run "^TestConsistencyCheck\$" \
            -args -datadir "${NODE_DIR}/${NODE_ID}" -v 2>&1 || {
            log_error "Consistency check FAILED after crash ${crash_iter}"
            fail_cnt=$((fail_cnt + 1))
        }
    fi

    # ---------------------------------------------------------------------------
    # Phase 4: Restart and verify
    # ---------------------------------------------------------------------------
    log_info "Restarting node ..."
    ${NODE_BINARY} --data-dir "${NODE_DIR}" > /tmp/protocol-node.log 2>&1 &
    sleep 5

    PID=$(find_pid)
    if [ -z "$PID" ]; then
        log_error "Node failed to restart after crash ${crash_iter}! Check /tmp/protocol-node.log"
        # Don't exit immediately — allow next iteration or final check
        log_warn "Contents of /tmp/protocol-node.log:"
        tail -20 /tmp/protocol-node.log
        exit 2
    fi
    log_info "Node restarted with PID ${PID}"

    HEIGHT_AFTER=$(find_block_height)
    log_info "Height after restart: ${HEIGHT_AFTER}"

    # The height should be >= what it was before (worst case: no blocks lost)
    if [ "$HEIGHT_AFTER" -lt "$HEIGHT_BEFORE" ] 2>/dev/null; then
        log_error "Height DROPPED after restart! Before: ${HEIGHT_BEFORE}, After: ${HEIGHT_AFTER}"
        log_error "This indicates blocks committed to LevelDB's write-ahead log were lost."
        fail_cnt=$((fail_cnt + 1))
    else
        log_info "Height preserved/increased: ${HEIGHT_BEFORE} -> ${HEIGHT_AFTER}"
        pass_cnt=$((pass_cnt + 1))
    fi

    sleep 2
done

# ---------------------------------------------------------------------------
# Phase 5: Final verification
# ---------------------------------------------------------------------------
echo ""
log_info "=== Final consistency check ==="

HEIGHT_FINAL=$(find_block_height)
log_info "Final block height: ${HEIGHT_FINAL}"

# Kill the node one last time for a clean check
PID=$(find_pid)
if [ -n "$PID" ]; then
    log_info "Shutting down node for final check..."
    kill "$PID" 2>/dev/null || true
    sleep 3
fi

# Final check with Go test
if [ -f "$CHECK_SCRIPT" ]; then
    bash "$CHECK_SCRIPT" "${NODE_DIR}" "${NODE_ID}" || {
        log_error "Final consistency check FAILED!"
        fail_cnt=$((fail_cnt + 1))
    }
else
    cd "${PROTOCOL_DIR}" && go test ./src/state/ -run "^TestConsistencyCheck\$" \
        -args -datadir "${NODE_DIR}/${NODE_ID}" -v 2>&1 || {
        log_error "Final consistency check FAILED!"
        fail_cnt=$((fail_cnt + 1))
    }
fi

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
echo ""
log_info "=== Results ==="
log_info "Passes: ${pass_cnt}"
log_info "Failures: ${fail_cnt}"

if [ "${fail_cnt}" -eq 0 ]; then
    log_info "${GREEN}ALL CRASH-RECOVERY CHECKS PASSED${NC}"
    exit 0
else
    log_error "${RED}${fail_cnt} CRASH-RECOVERY CHECK(S) FAILED${NC}"
    exit 1
fi
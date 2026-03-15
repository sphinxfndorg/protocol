# Complete Network Local Development Setup

# 1. CLEANUP & DATA MANAGEMENT
# -----------------------------
# Remove existing blockchain data (choose one):

# Option A: Remove only node data (keep other data)
```bash
rm -rf data/Node-*
```

# Option B: Complete reset (remove all data)
```bash
rm -rf data/
```


# 2. RUN LOCAL TEST NETWORK
# -------------------------
```bash
cd src/cli && go run main.go -test-nodes=3
```


# 3. RUN TEST SUITES
# ------------------

# A. Genesis + Block Building tests (argon2 slow - needs 300s)
```bash
go test ./src/core/... -v -timeout 300s \
  -run "TestBuildBlock|TestAllocationToTx|TestBuildAlloc|TestMerkle|TestValidateGenesisState|TestVerifyGenesisBlockHash|TestApplyGenesis|TestGenesisState|TestGenesisStateFromChainParams|TestNewGenesisValidatorStake|TestDefaultGenesisState"
```

# B. Allocation tests only (fast - 30s is fine)
```bash
go test ./src/core/... -v -timeout 30s \
  -run "TestAllocation|TestDefaultGenesis|TestSummarise|TestDeterministic|TestUint64|TestNewGenesisAllocation|TestDomainConstructors"
```

# C. Full test suite (everything)
```bash
go test ./src/core/... -v -timeout 300s \
  -run "TestBuildBlock|TestAllocationToTx|TestBuildAlloc|TestMerkle|TestValidateGenesisState|TestVerifyGenesisBlockHash|TestApplyGenesis|TestGenesisState|TestGenesisStateFromChainParams|TestNewGenesisValidatorStake|TestDefaultGenesisState|TestAllocation|TestDefaultGenesis|TestSummarise|TestDeterministic|TestUint64|TestNewGenesisAllocation|TestDomainConstructors"
```


# 4. GENERATE PERMANENT NODE DATA WITH LOGS
# -----------------------------------------
```bash
rm -rf data/ && go run ./src/cli/main.go -test-nodes 3 2>&1 | tee /tmp/out.txt
```


# 5. QUICK REFERENCE - ALL COMMANDS IN ORDER
# -----------------------------------------
# Complete workflow from clean slate to full test run:
```bash
rm -rf data/
cd src/cli
go run main.go -test-nodes=3
cd ../..
go test ./src/core/... -v -timeout 300s -run "TestBuildBlock|TestAllocationToTx|TestBuildAlloc|TestMerkle|TestValidateGenesisState|TestVerifyGenesisBlockHash|TestApplyGenesis|TestGenesisState|TestGenesisStateFromChainParams|TestNewGenesisValidatorStake|TestDefaultGenesisState|TestAllocation|TestDefaultGenesis|TestSummarise|TestDeterministic|TestUint64|TestNewGenesisAllocation|TestDomainConstructors"
```
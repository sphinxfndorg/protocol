// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/params.go
package core

import (
	"fmt"
	"math/big"
	"time"

	"github.com/sphinxorg/protocol/src/accounts/key"
	"github.com/sphinxorg/protocol/src/pool"
)

// GetChainParams returns the chain parameters from the mock provider
// This implements the ChainParamsProvider interface
func (m *MockChainParamsProvider) GetChainParams() *SphinxChainParameters {
	return m.params // Return the stored parameters
}

// GetWalletDerivationPaths now delegates to the centralized keystore package
// Returns the appropriate BIP44 derivation paths for the current network
func (m *MockChainParamsProvider) GetWalletDerivationPaths() map[string]string {
	// Get the appropriate keystore config based on chain parameters
	var keystoreConfig *key.KeystoreConfig

	// Select the correct keystore configuration based on network type
	switch {
	case m.params.IsMainnet():
		keystoreConfig = key.GetMainnetKeystoreConfig()
	case m.params.IsTestnet():
		keystoreConfig = key.GetTestnetKeystoreConfig()
	case m.params.IsDevnet():
		keystoreConfig = key.GetDevnetKeystoreConfig()
	default:
		// Fallback to mainnet if network type cannot be determined
		keystoreConfig = key.GetMainnetKeystoreConfig()
	}

	// Return the wallet derivation paths from the selected keystore config
	return keystoreConfig.GetWalletDerivationPaths()
}

// GetSphinxChainParams returns the mainnet parameters
// This is the primary function that defines all mainnet chain parameters
func GetSphinxChainParams() *SphinxChainParameters {
	// Use the STANDARDIZED genesis hash that all nodes will use
	// This ensures all nodes have the same genesis block
	genesisHash := GetGenesisHash()

	// Return complete mainnet configuration
	return &SphinxChainParameters{
		// Network Identification - unique identifiers for the blockchain
		ChainID:       7331,             // Unique chain identifier
		ChainName:     "Sphinx Mainnet", // Human-readable network name
		Symbol:        "SPX",            // Token symbol
		GenesisTime:   1732070400,       // Fixed genesis timestamp - MUST MATCH genesisBlockDefinition
		GenesisHash:   genesisHash,      // Genesis block hash
		Version:       "1.0.0",          // Protocol version
		MagicNumber:   0x53504858,       // "SPHX" - Magic number for message validation
		DefaultPort:   32307,            // Default P2P port
		BIP44CoinType: 7331,             // BIP44 coin type for wallet derivation
		LedgerName:    "Sphinx",         // Ledger hardware wallet app name

		// Denominations - unit conversions for the native token
		Denominations: map[string]*big.Int{
			"nSPX": big.NewInt(1),    // Base unit (nano SPX) - smallest unit
			"gSPX": big.NewInt(1e9),  // Giga SPX = 1,000,000,000 nSPX
			"SPX":  big.NewInt(1e18), // Main unit = 1,000,000,000,000,000,000 nSPX
		},

		// Block Configuration - size and gas limits
		MaxBlockSize:       2 * 1024 * 1024,        // 2MB - maximum block size
		MaxTransactionSize: 100 * 1024,             // 100KB - maximum transaction size
		TargetBlockSize:    1 * 1024 * 1024,        // 1MB - target block size for optimization
		BlockGasLimit:      big.NewInt(10000000),   // 10 million gas - maximum gas per block
		BaseBlockReward:    big.NewInt(5000000000), // 5 SPX in base units - block mining reward

		// Genesis-specific configuration - MUST MATCH genesisBlockDefinition
		GenesisConfig: &GenesisConfig{
			InitialDifficulty: big.NewInt(17179869184),                                       // Initial mining difficulty
			InitialGasLimit:   big.NewInt(5000),                                              // Initial gas limit per block
			GenesisNonce:      66,                                                            // Genesis block nonce
			GenesisExtraData:  []byte("Sphinx Network Genesis Block - Decentralized Future"), // Genesis message
		},

		// Mempool Configuration - transaction pool settings
		MempoolConfig: GetDefaultMempoolConfig(),

		// Consensus Configuration - PBFT/RANDAO settings
		ConsensusConfig: GetDefaultConsensusConfig(),

		// Performance Configuration - node optimization settings
		PerformanceConfig: GetDefaultPerformanceConfig(),
	}
}

// GetDefaultMempoolConfig returns the default mempool configuration
// Defines how the transaction pool behaves
func GetDefaultMempoolConfig() *pool.MempoolConfig {
	return &pool.MempoolConfig{
		MaxSize:           10000,                // Maximum number of transactions in mempool
		MaxBytes:          100 * 1024 * 1024,    // 100MB - maximum mempool size in bytes
		MaxTxSize:         100 * 1024,           // 100KB - maximum transaction size
		BlockGasLimit:     big.NewInt(10000000), // 10 million gas - matches block gas limit
		ValidationTimeout: 30 * time.Second,     // Timeout for transaction validation
		ExpiryTime:        24 * time.Hour,       // How long transactions stay in mempool
		MaxBroadcastSize:  5000,                 // Maximum transactions to broadcast at once
		MaxPendingSize:    5000,                 // Maximum pending transactions
	}
}

// GetDefaultConsensusConfig returns the default consensus configuration
// Defines how the PBFT consensus with RANDAO operates
func GetDefaultConsensusConfig() *ConsensusConfig {
	// Calculate 32 SPX in base units (nSPX)
	// 32 * 1e18 = 32,000,000,000,000,000,000 nSPX
	minStakeNSPX := new(big.Int).Mul(
		big.NewInt(32),   // 32 SPX minimum stake requirement
		big.NewInt(1e18), // 1e18 nSPX per SPX
	)

	return &ConsensusConfig{
		BlockTime:        10 * time.Second,               // Target time between blocks
		EpochLength:      100,                            // Number of slots per epoch
		ValidatorSetSize: 21,                             // Number of active validators
		MaxValidators:    100,                            // Maximum total validators
		MinStakeAmount:   minStakeNSPX,                   // Minimum stake to become validator (32 SPX)
		UnbondingPeriod:  7 * 24 * time.Hour,             // 7 days - time to unbond stake
		SlashingEnabled:  true,                           // Enable slashing for misbehavior
		DoubleSignSlash:  big.NewInt(500000000000000000), // 0.5 SPX penalty for double signing
	}
}

// GetDefaultPerformanceConfig returns the default performance configuration
// Defines node performance and optimization settings
func GetDefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		MaxConcurrentValidations: 100,              // Maximum parallel transaction validations
		ValidationTimeout:        30 * time.Second, // Timeout for validation operations
		CacheSize:                10000,            // Size of various caches
		PruningInterval:          5 * time.Minute,  // How often to prune old data
		MaxPeers:                 50,               // Maximum number of peer connections
		SyncBatchSize:            100,              // Blocks per sync batch
	}
}

// GetTestnetChainParams returns testnet parameters
// Testnet is used for testing before mainnet deployment
func GetTestnetChainParams() *SphinxChainParameters {
	// Start with mainnet params as base
	params := GetSphinxChainParams()

	// Override with testnet-specific values
	params.ChainName = "Sphinx Testnet"
	params.ChainID = 17331
	params.DefaultPort = 32308
	params.BIP44CoinType = 1 // Same as devnet, different from mainnet
	params.LedgerName = "Sphinx Testnet"

	// Testnet-specific adjustments for easier testing
	params.MaxBlockSize = 4 * 1024 * 1024       // 4MB for testing - larger blocks
	params.BlockGasLimit = big.NewInt(20000000) // 20 million gas for testing - double mainnet

	// Faster block times for testing to speed up test execution
	params.ConsensusConfig.BlockTime = 5 * time.Second // Half of mainnet
	params.ConsensusConfig.EpochLength = 50            // Shorter epochs

	return params
}

// GetDevnetChainParams returns development network parameters
// Devnet is used for local development and debugging
func GetDevnetChainParams() *SphinxChainParameters {
	// Start with mainnet params as base
	params := GetSphinxChainParams()

	// Override with devnet-specific values
	params.ChainName = "Sphinx Devnet"
	params.ChainID = 7331 // Same as mainnet but different name
	params.DefaultPort = 32309
	params.BIP44CoinType = 1 // Different from mainnet (7331)
	params.LedgerName = "Sphinx Devnet"

	// Development-specific adjustments for maximum flexibility
	params.MaxBlockSize = 8 * 1024 * 1024       // 8MB for development - largest blocks
	params.BlockGasLimit = big.NewInt(50000000) // 50 million gas for development - 5x mainnet

	// Very fast block times for rapid development and testing
	params.ConsensusConfig.BlockTime = 2 * time.Second // 5x faster than mainnet
	params.ConsensusConfig.EpochLength = 10            // Very short epochs

	// For devnet, you can either keep 32 SPX or lower it for testing
	// If you want to test with lower stakes during development:
	devnetMinStake := new(big.Int).Mul(
		big.NewInt(1), // 1 SPX for devnet testing (optional)
		big.NewInt(1e18),
	)
	// OR keep 32 SPX to match mainnet (uncomment to use):
	// devnetMinStake := new(big.Int).Mul(
	//     big.NewInt(32),
	//     big.NewInt(1e18),
	// )
	params.ConsensusConfig.MinStakeAmount = devnetMinStake

	return params
}

// GetMempoolConfigFromChainParams extracts mempool config from chain params
// Helper function to safely access mempool configuration
func GetMempoolConfigFromChainParams(chainParams *SphinxChainParameters) *pool.MempoolConfig {
	// Handle nil parameters or missing mempool config
	if chainParams == nil || chainParams.MempoolConfig == nil {
		return GetDefaultMempoolConfig() // Fallback to defaults
	}
	return chainParams.MempoolConfig
}

// ValidateChainParams validates the chain parameters
// Ensures all parameters are within acceptable ranges and consistent
func ValidateChainParams(params *SphinxChainParameters) error {
	// Check for nil parameters
	if params == nil {
		return fmt.Errorf("chain parameters cannot be nil")
	}

	// Chain ID must be non-zero (unique identifier)
	if params.ChainID == 0 {
		return fmt.Errorf("chain ID cannot be zero")
	}

	// Block size must be positive
	if params.MaxBlockSize == 0 {
		return fmt.Errorf("max block size cannot be zero")
	}

	// Transaction size cannot exceed block size
	if params.MaxTransactionSize > params.MaxBlockSize {
		return fmt.Errorf("max transaction size cannot exceed max block size")
	}

	// Gas limit must be positive
	if params.BlockGasLimit == nil || params.BlockGasLimit.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("block gas limit must be positive")
	}

	// Mempool transaction size cannot exceed chain max transaction size
	if params.MempoolConfig != nil {
		if params.MempoolConfig.MaxTxSize > params.MaxTransactionSize {
			return fmt.Errorf("mempool max transaction size cannot exceed chain max transaction size")
		}
	}

	return nil
}

// GetNetworkName returns human-readable network name
// Provides a user-friendly network identifier
func (p *SphinxChainParameters) GetNetworkName() string {
	switch p.ChainID {
	case 7331:
		// ChainID 7331 could be either Mainnet or Devnet - check name
		if p.ChainName == "Sphinx Devnet" {
			return "Sphinx Devnet"
		}
		return "Sphinx Mainnet"
	case 17331:
		return "Sphinx Testnet"
	default:
		// Unknown chain ID, default to devnet
		return "Sphinx Devnet"
	}
}

// IsMainnet returns true if this is mainnet configuration
// Identifies production mainnet
func (p *SphinxChainParameters) IsMainnet() bool {
	return p.ChainID == 7331 && p.ChainName == "Sphinx Mainnet"
}

// IsTestnet returns true if this is testnet configuration
// Identifies test network
func (p *SphinxChainParameters) IsTestnet() bool {
	return p.ChainID == 17331
}

// IsDevnet returns true if this is devnet configuration
// Identifies development network
func (p *SphinxChainParameters) IsDevnet() bool {
	return p.ChainID == 7331 && p.ChainName == "Sphinx Devnet"
}

// GetStakeDenomination returns the stake denomination
// Returns the human-readable unit for stake amounts
func (p *SphinxChainParameters) GetStakeDenomination() string {
	return "SPX"
}

// ConvertToBaseUnits converts amount to base units (nSPX)
// Converts from any denomination to the smallest unit
func (p *SphinxChainParameters) ConvertToBaseUnits(amount *big.Int, fromDenom string) (*big.Int, error) {
	// Look up the multiplier for the source denomination
	multiplier, exists := p.Denominations[fromDenom]
	if !exists {
		return nil, fmt.Errorf("unknown denomination: %s", fromDenom)
	}
	// Multiply amount by multiplier to get base units
	return new(big.Int).Mul(amount, multiplier), nil
}

// ConvertFromBaseUnits converts amount from base units to target denomination
// Converts from smallest unit to any other denomination
func (p *SphinxChainParameters) ConvertFromBaseUnits(amount *big.Int, toDenom string) (*big.Int, error) {
	// Look up the multiplier for the target denomination
	multiplier, exists := p.Denominations[toDenom]
	if !exists {
		return nil, fmt.Errorf("unknown denomination: %s", toDenom)
	}
	// Divide amount by multiplier to get target denomination
	return new(big.Int).Div(amount, multiplier), nil
}

// GetKeystoreConfig returns the appropriate keystore configuration for these chain parameters
// Provides the correct key management settings for the current network
func (p *SphinxChainParameters) GetKeystoreConfig() *key.KeystoreConfig {
	switch {
	case p.IsMainnet():
		return key.GetMainnetKeystoreConfig()
	case p.IsTestnet():
		return key.GetTestnetKeystoreConfig()
	case p.IsDevnet():
		return key.GetDevnetKeystoreConfig()
	default:
		// Default to mainnet for safety
		return key.GetMainnetKeystoreConfig()
	}
}

// GenerateLedgerHeaders generates headers specifically formatted for Ledger hardware
// This method now delegates to the centralized keystore package
func (p *SphinxChainParameters) GenerateLedgerHeaders(operation string, amount float64, address string, memo string) string {
	// Get appropriate keystore config for this network
	keystoreConfig := p.GetKeystoreConfig()
	// Delegate to keystore's Ledger header generator
	return keystoreConfig.GenerateLedgerHeaders(operation, amount, address, memo)
}

// GetMaxBlockSize returns the maximum block size in bytes
// Getter for maximum block size
func (p *SphinxChainParameters) GetMaxBlockSize() uint64 {
	return p.MaxBlockSize
}

// GetTargetBlockSize returns the target block size in bytes
// Getter for target block size (optimization target)
func (p *SphinxChainParameters) GetTargetBlockSize() uint64 {
	return p.TargetBlockSize
}

// GetMaxTransactionSize returns the maximum transaction size in bytes
// Getter for maximum transaction size
func (p *SphinxChainParameters) GetMaxTransactionSize() uint64 {
	return p.MaxTransactionSize
}

// IsBlockSizeValid checks if a block size is within acceptable limits
// Validates block size against chain parameters
func (p *SphinxChainParameters) IsBlockSizeValid(blockSize uint64) bool {
	// Block must not exceed maximum and must be positive
	return blockSize <= p.MaxBlockSize && blockSize > 0
}

// GetRecommendedBlockSize returns a recommended block size (could be target or a percentage of max)
// Provides an optimal block size for miners/validators
func (p *SphinxChainParameters) GetRecommendedBlockSize() uint64 {
	// Use target size if set and valid, otherwise use 90% of max size
	if p.TargetBlockSize > 0 && p.TargetBlockSize < p.MaxBlockSize {
		return p.TargetBlockSize
	}
	// Default to 90% of maximum to leave room for growth
	return p.MaxBlockSize * 90 / 100
}

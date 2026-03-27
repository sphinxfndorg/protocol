// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

// go/src/common/config.go
package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DataDir is the unified data directory for all node data
	DataDir = "data"
)

// WriteJSONToFile writes data to JSON file in output directory
func WriteJSONToFile(data interface{}, filename string) error {
	outputDir := filepath.Join(DataDir, "output")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	filePath := filepath.Join(outputDir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

// GetNodeIdentifier returns a unique node identifier from address
func GetNodeIdentifier(address string) string {
	return fmt.Sprintf("Node-%s", address)
}

// GetNodePortFromAddress extracts port from address for identification
func GetNodePortFromAddress(address string) string {
	parts := strings.Split(address, ":")
	if len(parts) == 2 {
		return parts[1]
	}
	return address
}

// GetNodeDataDir returns the root data directory for a node
func GetNodeDataDir(address string) string {
	nodeIdentifier := GetNodeIdentifier(address)
	return filepath.Join(DataDir, nodeIdentifier)
}

// GetLevelDBPath returns the path for the main LevelDB database file
// This is where blocks, indices, and transactions are stored
func GetLevelDBPath(address string) string {
	return filepath.Join(GetNodeDataDir(address), "blockchain.db")
}

// GetStateDBPath returns the path for the state LevelDB database file
// This is for separate state storage (optional, can be the same as main DB)
func GetStateDBPath(address string) string {
	return filepath.Join(GetNodeDataDir(address), "state.db")
}

// GetBlockchainDataDir returns the directory for JSON backups and chain state
func GetBlockchainDataDir(address string) string {
	return filepath.Join(GetNodeDataDir(address), "blockchain")
}

// GetBlocksDir returns the directory for block JSON files
func GetBlocksDir(address string) string {
	return filepath.Join(GetBlockchainDataDir(address), "blocks")
}

// GetIndexDir returns the directory for block indices
func GetIndexDir(address string) string {
	return filepath.Join(GetBlockchainDataDir(address), "index")
}

// GetStateDir returns the directory for chain state JSON files
func GetStateDir(address string) string {
	return filepath.Join(GetBlockchainDataDir(address), "state")
}

// GetMetricsDir returns the directory for performance metrics
func GetMetricsDir(address string) string {
	return filepath.Join(GetBlockchainDataDir(address), "metrics")
}

// GetChainStatePath returns the path to the chain state JSON file
func GetChainStatePath(address string) string {
	return filepath.Join(GetStateDir(address), "chain_state.json")
}

// GetCheckpointPath returns the path to the chain checkpoint JSON file
// This is stored in the state directory alongside chain_state.json
func GetCheckpointPath(address string) string {
	return filepath.Join(GetStateDir(address), "chain_checkpoint.json")
}

// GetTPSMetricsPath returns the path to the TPS metrics JSON file
// Now stored in the metrics directory
func GetTPSMetricsPath(address string) string {
	return filepath.Join(GetMetricsDir(address), "tps_metrics.json")
}

// GetKeysDataDir returns the directory for cryptographic keys
func GetKeysDataDir(address string) string {
	return filepath.Join(GetNodeDataDir(address), "keys")
}

// GetPrivateKeyPath returns the path to the private key file
func GetPrivateKeyPath(address string) string {
	return filepath.Join(GetKeysDataDir(address), "private.key")
}

// GetPublicKeyPath returns the path to the public key file
func GetPublicKeyPath(address string) string {
	return filepath.Join(GetKeysDataDir(address), "public.key")
}

// GetNodeInfoPath returns the path to the node info JSON file
func GetNodeInfoPath(address string) string {
	return filepath.Join(GetKeysDataDir(address), "node_info.json")
}

// EnsureNodeDirs creates all necessary directories for a node
// Creates the complete directory structure:
//
//	data/Node-{address}/
//	├── blockchain.db          (file, not directory)
//	├── state.db               (file, not directory)
//	└── blockchain/
//	    ├── blocks/            (block JSON files)
//	    ├── index/             (block indices)
//	    ├── state/             (chain state JSON)
//	    │   ├── chain_state.json
//	    │   └── chain_checkpoint.json
//	    └── metrics/           (performance metrics)
//	        └── tps_metrics.json
//	└── keys/                  (cryptographic keys)
func EnsureNodeDirs(address string) error {
	// Create the root node directory
	nodeDir := GetNodeDataDir(address)
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		return fmt.Errorf("failed to create node directory %s: %w", nodeDir, err)
	}

	// Create all subdirectories
	dirs := []string{
		GetBlocksDir(address),   // blockchain/blocks/
		GetIndexDir(address),    // blockchain/index/
		GetStateDir(address),    // blockchain/state/
		GetMetricsDir(address),  // blockchain/metrics/ (NEW)
		GetKeysDataDir(address), // keys/
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Note: blockchain.db and state.db are files, not directories
	// They will be created by the database when opened

	return nil
}

// WriteKeysToFile writes keys using network address
func WriteKeysToFile(address string, privateKey, publicKey []byte) error {
	if err := EnsureNodeDirs(address); err != nil {
		return err
	}

	privateKeyPath := GetPrivateKeyPath(address)
	if err := os.WriteFile(privateKeyPath, privateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	publicKeyPath := GetPublicKeyPath(address)
	if err := os.WriteFile(publicKeyPath, publicKey, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// ReadKeysFromFile reads keys using network address
func ReadKeysFromFile(address string) ([]byte, []byte, error) {
	privateKeyPath := GetPrivateKeyPath(address)
	publicKeyPath := GetPublicKeyPath(address)

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// KeysExist checks if keys exist for a network address
func KeysExist(address string) bool {
	privateKeyPath := GetPrivateKeyPath(address)
	publicKeyPath := GetPublicKeyPath(address)

	_, privateErr := os.Stat(privateKeyPath)
	_, publicErr := os.Stat(publicKeyPath)

	return privateErr == nil && publicErr == nil
}

// WriteNodeInfo writes node information using network address
func WriteNodeInfo(address string, nodeInfo map[string]interface{}) error {
	if err := EnsureNodeDirs(address); err != nil {
		return err
	}

	nodeInfoPath := GetNodeInfoPath(address)
	file, err := os.Create(nodeInfoPath)
	if err != nil {
		return fmt.Errorf("failed to create node info file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(nodeInfo); err != nil {
		return fmt.Errorf("failed to encode node info: %w", err)
	}

	return nil
}

// ReadNodeInfo reads node information using network address
func ReadNodeInfo(address string) (map[string]interface{}, error) {
	nodeInfoPath := GetNodeInfoPath(address)
	data, err := os.ReadFile(nodeInfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read node info: %w", err)
	}

	var nodeInfo map[string]interface{}
	if err := json.Unmarshal(data, &nodeInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node info: %w", err)
	}

	return nodeInfo, nil
}

// GetNodeDataDirs returns a map of all important directories for a node
// Useful for debugging and validation
func GetNodeDataDirs(address string) map[string]string {
	return map[string]string{
		"node_root":     GetNodeDataDir(address),
		"blockchain":    GetBlockchainDataDir(address),
		"blocks":        GetBlocksDir(address),
		"index":         GetIndexDir(address),
		"state":         GetStateDir(address),
		"metrics":       GetMetricsDir(address),
		"keys":          GetKeysDataDir(address),
		"leveldb_main":  GetLevelDBPath(address),
		"leveldb_state": GetStateDBPath(address),
		"chain_state":   GetChainStatePath(address),
		"checkpoint":    GetCheckpointPath(address),
		"tps_metrics":   GetTPSMetricsPath(address),
	}
}

// CleanNodeData removes all data for a node
// Use with caution - this will delete all blockchain data and keys
func CleanNodeData(address string) error {
	nodeDir := GetNodeDataDir(address)
	if err := os.RemoveAll(nodeDir); err != nil {
		return fmt.Errorf("failed to remove node data directory %s: %w", nodeDir, err)
	}
	return nil
}

// GetCheckpointDir returns the directory containing checkpoint files
// This is the same as GetStateDir()
func GetCheckpointDir(address string) string {
	return GetStateDir(address)
}

// GetBlockchainCheckpointPath returns the path to the checkpoint file
// for a given blockchain data directory (used during promotion)
func GetBlockchainCheckpointPath(blockchainDataDir string) string {
	return filepath.Join(blockchainDataDir, "state", "chain_checkpoint.json")
}

// GetCheckpointFromDataDir returns the checkpoint path from a node's data directory
// This is a convenience function that takes the node's base address
func GetCheckpointFromDataDir(address string) string {
	return GetCheckpointPath(address)
}

// EnsureCheckpointDir ensures the checkpoint directory exists
func EnsureCheckpointDir(address string) error {
	checkpointDir := GetCheckpointDir(address)
	if err := os.MkdirAll(checkpointDir, 0755); err != nil {
		return fmt.Errorf("failed to create checkpoint directory %s: %w", checkpointDir, err)
	}
	return nil
}

// EnsureMetricsDir ensures the metrics directory exists
func EnsureMetricsDir(address string) error {
	metricsDir := GetMetricsDir(address)
	if err := os.MkdirAll(metricsDir, 0755); err != nil {
		return fmt.Errorf("failed to create metrics directory %s: %w", metricsDir, err)
	}
	return nil
}

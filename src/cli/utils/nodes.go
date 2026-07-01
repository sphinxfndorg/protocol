// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/nodes.go
//
// CLI node startup — delegates to bind package.
// All node startup logic is in src/bind/nodes.go and src/bind/helpers.go.

package utils

import (
	"github.com/sphinxfndorg/protocol/src/bind"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/network"
)

// StartNode delegates to bind.StartNode.
// This is a thin wrapper so CLI code can use utils.StartNode(...).
//
// rewardAddress is the operator's SPIF wallet address — see the docs on
// bind.StartNode for what it is and is not used for.
func StartNode(
	dataDir string,
	nodeConfig network.NodePortConfig,
	totalNodes, nodeIndex int,
	vdfParams *consensus.VDFParams,
	networkType string,
	seeds string,
	rewardAddress string,
) error {
	return bind.StartNode(dataDir, nodeConfig, totalNodes, nodeIndex, vdfParams, networkType, seeds, rewardAddress)
}

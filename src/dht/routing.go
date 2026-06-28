// Copyright 2024 Lei Ni (nilei81@gmail.com)
//
// This library follows a dual licensing model -
//
// - it is licensed under the 2-clause BSD license if you have written evidence showing that you are a licensee of github.com/lni/pothos
// - otherwise, it is licensed under the GPL-2 license
//
// See the LICENSE file for details
// https://github.com/lni/dht/tree/main
//
// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/dht/routing.go
package dht

import (
	"net"
	"sort"
	"time"

	"github.com/elliotchance/orderedmap/v2"
	"github.com/sphinxfndorg/protocol/src/network"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

// Constants for Kademlia routing table configuration
const (
	// DefaultK is the bucket size (k) - number of nodes stored per k-bucket
	// Standard Kademlia uses k=20, here we use 16
	DefaultK int = 16

	// DefaultBits is the size of node IDs in bits (256 bits for SHA-256)
	// Changed from 128 to 256 for better security and larger address space
	DefaultBits int = 256

	// staleThreshold - nodes not seen for this long are considered stale
	// and will be pinged to check liveness
	staleThreshold = 180 * time.Second

	// deadThreshold - nodes not seen for this long are considered dead
	// and will be removed from the routing table
	deadThreshold = 480 * time.Second
)

// newBucket creates a new k-bucket for the routing table
// Each bucket stores nodes with a specific common prefix length
func newBucket(k int) *kBucket {
	return &kBucket{
		k:       k,                                                    // Bucket capacity (k parameter)
		buckets: orderedmap.NewOrderedMap[rpc.NodeID, remoteRecord](), // Ordered map maintains insertion order (LRU)
	}
}

// Len returns the number of nodes in this bucket
func (b *kBucket) Len() int {
	return b.buckets.Len()
}

// Observe updates or adds a node record in the bucket
// Implements the Kademlia bucket update rule: move seen node to front (LRU)
func (b *kBucket) Observe(nodeID rpc.NodeID, address net.UDPAddr) {
	// Create a record with current timestamp
	rec := remoteRecord{
		remote: rpc.Remote{
			NodeID:  nodeID,
			Address: address,
		},
		lastSeen: time.Now(), // Update last seen time
	}

	// Get current bucket size
	sz := b.buckets.Len()

	// Case 1: Bucket not full - simply add the node
	if sz < b.k {
		b.buckets.Set(nodeID, rec) // Set will move to front if exists, add if new
		return
	}

	// Case 2: Bucket at capacity (sz == k)
	if sz == b.k {
		// Check if node already exists in bucket
		if _, ok := b.buckets.Get(nodeID); ok {
			// Node exists - update its record and move to front
			b.buckets.Set(nodeID, rec)
			return
		}

		// Node doesn't exist - need to evict least recently used node
		// Get the front (oldest) element from ordered map
		if el := b.buckets.Front(); el != nil {
			// Remove oldest node and add new one
			b.buckets.Delete(el.Key)
			b.buckets.Set(nodeID, rec)
			return
		}

		// Should never happen if sz == k but bucket has no elements
		panic("el == nil")
	}

	// Bucket should never exceed k elements
	panic("more than k elements in the bucket")
}

// CopyToList copies all remote nodes from the bucket into the provided slice
// Returns the appended slice for chaining
func (b *kBucket) CopyToList(l []rpc.Remote) []rpc.Remote {
	// Iterate through ordered map from front (oldest) to back (newest)
	for el := b.buckets.Front(); el != nil; el = el.Next() {
		// Append each node's remote info to the slice
		l = append(l, el.Value.remote)
	}
	return l
}

// routingTable implements the Kademlia routing table structure
// It consists of multiple k-buckets, one for each bit of the node ID
type routingTable struct {
	k       int          // Bucket size (k parameter)
	bits    int          // Number of bits in node ID (256)
	nodeID  rpc.NodeID   // This node's ID
	address net.UDPAddr  // This node's address
	empty   []rpc.NodeID // Temporary slice for empty bucket tracking
	stale   []rpc.Remote // Temporary slice for stale node tracking
	buckets []*kBucket   // Array of k-buckets, one per bit
}

// newRoutingTable creates a new Kademlia routing table
// Initializes buckets for each possible common prefix length
func newRoutingTable(k int, bits int, selfID rpc.NodeID, addr net.UDPAddr) *routingTable {
	// Create routing table with pre-allocated slices
	rt := &routingTable{
		k:       k,
		bits:    bits,
		nodeID:  selfID,
		address: addr,
		empty:   make([]rpc.NodeID, 0, bits),   // Pre-allocate capacity
		stale:   make([]rpc.Remote, 0, k*bits), // Pre-allocate capacity
		buckets: make([]*kBucket, bits),        // One bucket per bit
	}

	// Initialize each bucket
	for i := 0; i < bits; i++ {
		rt.buckets[i] = newBucket(k)
	}
	return rt
}

// Observe adds or updates a node in the appropriate bucket
// The bucket is determined by the common prefix length with this node
func (r *routingTable) Observe(nodeID rpc.NodeID, address net.UDPAddr) {
	// Calculate common prefix length between this node and the observed node
	prefixLen := network.Key(r.nodeID).CommonPrefixLength(network.Key(nodeID))

	// If they share all bits (same node), ignore (can't add self to routing table)
	if prefixLen == r.bits {
		return
	}

	// Add to the bucket corresponding to this prefix length
	b := r.buckets[prefixLen]
	b.Observe(nodeID, address)
}

// InterestedNodes returns node IDs that would fill empty buckets
// Used during bucket refill to find nodes for empty buckets
func (r *routingTable) InterestedNodes() []rpc.NodeID {
	// Reset empty slice
	empty := r.empty[:0]

	// Check each bucket
	for i := 0; i < r.bits; i++ {
		// If bucket is empty, we're interested in nodes for this prefix
		if b := r.buckets[i]; b.Len() == 0 {
			// Generate a random node ID that would fall into this bucket
			v := r.getRandomInterestedNodeID(i)
			empty = append(empty, v)
		}
	}
	return empty
}

// GetStaleRemote returns nodes that haven't been seen recently
// These nodes should be pinged to check if they're still alive
func (r *routingTable) GetStaleRemote() []rpc.Remote {
	// Reset stale slice
	stale := r.stale[:0]
	now := time.Now()

	// Check all buckets
	for _, b := range r.buckets {
		// Iterate through each node in the bucket
		for el := b.buckets.Front(); el != nil; el = el.Next() {
			rec := el.Value
			// If node hasn't been seen since staleThreshold, add to stale list
			if now.Sub(rec.lastSeen) > staleThreshold {
				stale = append(stale, rec.remote)
			}
		}
	}
	return stale
}

// GC performs garbage collection on the routing table
// Removes nodes that haven't been seen for longer than deadThreshold
func (r *routingTable) GC() {
	now := time.Now()

	// Check all buckets
	for _, b := range r.buckets {
		// Collect nodes to remove
		var toRemove []rpc.NodeID
		for el := b.buckets.Front(); el != nil; el = el.Next() {
			rec := el.Value
			// If node hasn't been seen since deadThreshold, mark for removal
			if now.Sub(rec.lastSeen) > deadThreshold {
				toRemove = append(toRemove, rec.remote.NodeID)
			}
		}
		// Remove dead nodes
		for _, nodeID := range toRemove {
			b.buckets.Delete(nodeID)
		}
	}
}

// KNearest returns the k closest nodes to a target node ID
// This is the core lookup operation in Kademlia
func (r *routingTable) KNearest(target rpc.NodeID) []rpc.Remote {
	// Validate target is not empty
	if network.Key(target).IsEmpty() {
		panic("empty target")
	}

	// Slice to collect candidate nodes
	var selected []rpc.Remote

	// Calculate common prefix length between this node and target
	prefixLen := network.Key(r.nodeID).CommonPrefixLength(network.Key(target))

	// If target is this node itself, return nil (no nodes needed)
	if prefixLen == r.bits {
		return nil
	}

	// Start with the bucket that shares the same prefix as target
	// This bucket contains nodes closest to the target
	b := r.buckets[prefixLen]
	selected = b.CopyToList(selected)

	// Collect from buckets with shorter prefixes (closer to target)
	i := prefixLen - 1
	added := 0
	for i >= 0 && added < r.k {
		cur := r.buckets[i]
		added += cur.Len()
		selected = cur.CopyToList(selected)
		i--
	}

	// Collect from buckets with longer prefixes (further from target)
	j := prefixLen + 1
	added = 0
	for j < len(r.buckets) && added < r.k {
		cur := r.buckets[j]
		added += cur.Len()
		selected = cur.CopyToList(selected)
		j++
	}

	// Add self as a candidate (useful for bootstrapping)
	selected = append(selected, r.self())

	// Sort all candidates by distance to target
	selected = sortByDistance(selected, target)

	// Return up to k closest nodes
	if len(selected) <= r.k {
		return selected
	}
	return selected[:r.k]
}

// self returns this node's own remote information
func (r *routingTable) self() rpc.Remote {
	return rpc.Remote{NodeID: r.nodeID, Address: r.address}
}

// sortByDistance sorts a slice of remotes by their XOR distance to a target
// Implements the Kademlia distance metric (XOR)
func sortByDistance(selected []rpc.Remote, target rpc.NodeID) []rpc.Remote {
	sort.Slice(selected, func(x, y int) bool {
		// Calculate XOR distances for both nodes
		var dx, dy network.Key
		dx.Distance(network.Key(selected[x].NodeID), network.Key(target))
		dy.Distance(network.Key(selected[y].NodeID), network.Key(target))
		// Compare distances (shorter distance means closer)
		return dx.Less(dy)
	})
	return selected
}

// getRandomInterestedNodeID generates a node ID that would fall into a specific bucket.
// Used to find nodes for empty buckets by generating a target in that bucket's range.
//
// prefixLen is the number of leading bits that must match r.nodeID (0-255 for a
// 256-bit NodeID). Flipping the bit immediately after that shared prefix yields an
// ID whose CommonPrefixLength with r.nodeID is exactly prefixLen, placing it in
// buckets[prefixLen]. The flip covers the full 32-byte ID (bits 0-255), not just
// bytes 0-7 and 16-23 as the previous high/low-uint64 version did.
func (r *routingTable) getRandomInterestedNodeID(prefixLen int) rpc.NodeID {
	// Start with this node's ID as base
	result := r.nodeID

	byteIdx := prefixLen / 8      // Which of the 32 bytes the target bit lives in
	bitIdx := 7 - (prefixLen % 8) // Bit position within that byte, MSB first

	result[byteIdx] ^= 1 << bitIdx // Flip the bit using XOR

	return result
}

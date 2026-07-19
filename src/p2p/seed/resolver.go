// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/dnsdiscovery/resolver.go
//
// DNS seed resolver — bridges the EIP-1459 DNS discovery client with the
// Sphinx P2P layer.  The resolver:
//
//   1. Detects enrtree:// URLs in a seed list (vs plain ip:port seeds).
//   2. Fetches, verifies, and traverses the DNS discovery tree.
//   3. Returns discovered peers as network.PeerInfo objects.
//
// This allows seamless mixing of plain TCP seeds and EIP-1459 DNS tree URLs
// in the same --seeds flag (e.g. "--seeds=enrtree://AEDA4B@nodes.sphinx.network,1.2.3.4:30303").

package dnsdiscovery

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/network"
)

// Resolver resolves DNS discovery trees into peer addresses.
// It wraps the Client and provides a simple interface for the P2P layer.
type Resolver struct {
	client  *Client
	timeout time.Duration
}

// NewResolver creates a new DNS resolver for peer discovery.
func NewResolver() *Resolver {
	return &Resolver{
		client:  NewClient(),
		timeout: 30 * time.Second,
	}
}

// AddTreesFromSeedList parses a comma-separated list of seeds and adds any
// enrtree:// URLs found in it to the resolver's discovery list.
// Returns the remaining seeds (those that are not enrtree:// URLs) so the
// caller can use them as plain TCP seeds.
func (r *Resolver) AddTreesFromSeedList(seedList string) (remainingSeeds []string) {
	if seedList == "" {
		return nil
	}

	seeds := strings.Split(seedList, ",")
	for _, seed := range seeds {
		seed = strings.TrimSpace(seed)
		if seed == "" {
			continue
		}

		if strings.HasPrefix(seed, ENRTreeScheme+"://") {
			if err := r.client.AddTreeURL(seed); err != nil {
				log.Printf("dnsdiscovery: failed to add tree URL %s: %v", seed, err)
			} else {
				log.Printf("dnsdiscovery: registered DNS discovery tree: %s", seed)
			}
		} else {
			remainingSeeds = append(remainingSeeds, seed)
		}
	}

	return remainingSeeds
}

// ResolvePeers performs DNS discovery and returns the list of discovered peers.
// Returns nil if no DNS trees are configured (caller should fall back to plain seeds).
func (r *Resolver) ResolvePeers(ctx context.Context) ([]network.PeerInfo, error) {
	if r.client == nil {
		return nil, fmt.Errorf("dnsdiscovery: resolver not initialized")
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.DiscoverPeers(ctxWithTimeout)
}

// HasTrees returns true if any DNS discovery trees are configured.
func (r *Resolver) HasTrees() bool {
	return r.client != nil && len(r.client.knownTreeURLs) > 0
}

// SetTimeout sets the resolver timeout.
func (r *Resolver) SetTimeout(timeout time.Duration) {
	r.timeout = timeout
}

// ============================================================================
// Integration helpers for the P2P Server
// ============================================================================

// SeedType indicates the type of a seed entry.
type SeedType int

const (
	// SeedPlain indicates a plain ip:port seed
	SeedPlain SeedType = iota
	// SeedDNSTree indicates an enrtree:// DNS discovery URL
	SeedDNSTree
)

// ClassifySeed determines whether a seed string is a plain address or an enrtree:// URL.
func ClassifySeed(seed string) SeedType {
	seed = strings.TrimSpace(seed)
	if strings.HasPrefix(seed, ENRTreeScheme+"://") {
		return SeedDNSTree
	}
	return SeedPlain
}

// FilterDNSTrees extracts enrtree:// URLs from a seed list, registers them with
// a new Resolver, and returns the plain seeds plus the resolver.
//
// Usage in the P2P layer:
//
//	plainSeeds, dnsResolver := dnsdiscovery.FilterDNSTrees(seedList)
//	server.seedNodes = plainSeeds // use as fallback
//	// Later: dnsResolver.ResolvePeers(ctx) to get DNS-discovered peers
func FilterDNSTrees(seedList string) (plainSeeds []string, resolver *Resolver) {
	resolver = NewResolver()
	plainSeeds = resolver.AddTreesFromSeedList(seedList)
	return plainSeeds, resolver
}

// ============================================================================
// DNS-based peer enrichment for the Server's DiscoverPeers
// ============================================================================

// EnrichPeersFromDNS is a convenience function that the P2P server can call
// alongside its existing DiscoverPeers logic.  It returns only the
// DNS-discovered peers that are not already in the provided knownPeers set.
//
// knownPeers is a set of "addr:port" strings to skip duplicates.
// seedList is the raw comma-separated seeds string.
func EnrichPeersFromDNS(seedList string, knownPeers map[string]bool) []network.PeerInfo {
	if seedList == "" {
		return nil
	}

	resolver := NewResolver()
	plainSeeds := resolver.AddTreesFromSeedList(seedList)

	// If no DNS trees were found in the seed list, skip
	if !resolver.HasTrees() {
		return nil
	}

	// Make the plain seeds available as a fallback for DNS lookup itself
	_ = plainSeeds

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	peers, err := resolver.ResolvePeers(ctx)
	if err != nil {
		log.Printf("dnsdiscovery: enrichment failed: %v", err)
		return nil
	}

	// Filter out already-known peers and invalid addresses
	var newPeers []network.PeerInfo
	for _, peer := range peers {
		if peer.Address == "" {
			continue
		}
		if knownPeers != nil && knownPeers[peer.Address] {
			continue
		}
		newPeers = append(newPeers, peer)
	}

	// Try to resolve the peers into dialable UDP addresses so we can
	// ping them for Kademlia integration. Peers that don't resolve are
	// dropped here — previously this loop only logged "skipping" without
	// actually removing them, so unresolvable peers were silently returned
	// to the caller anyway.
	resolvable := make([]network.PeerInfo, 0, len(newPeers))
	for _, peer := range newPeers {
		addrStr := peer.Address
		if peer.UDPPort != "" {
			// If we have a separate UDP port, use that for discovery pings
			if host, _, err := net.SplitHostPort(addrStr); err == nil {
				addrStr = net.JoinHostPort(host, peer.UDPPort)
			}
		}
		if _, err := net.ResolveUDPAddr("udp", addrStr); err != nil {
			log.Printf("dnsdiscovery: skipping unresolvable peer %s: %v", addrStr, err)
			continue
		}
		resolvable = append(resolvable, peer)
	}

	return resolvable
}

// HasDNSTreeSeeds checks if a seed list contains any enrtree:// URLs.
func HasDNSTreeSeeds(seedList string) bool {
	if seedList == "" {
		return false
	}
	for _, seed := range strings.Split(seedList, ",") {
		seed = strings.TrimSpace(seed)
		if strings.HasPrefix(seed, ENRTreeScheme+"://") {
			return true
		}
	}
	return false
}

// MergePeers merges DNS-discovered peers and seed-discovered peers,
// preferring the seed-discovered ones (they are already connected).
func MergePeers(dnsPeers []network.PeerInfo, seedPeers []network.PeerInfo) []network.PeerInfo {
	seen := make(map[string]bool)
	result := make([]network.PeerInfo, 0, len(dnsPeers)+len(seedPeers))

	// Seed peers first (higher priority)
	for _, p := range seedPeers {
		if p.Address != "" && !seen[p.Address] {
			result = append(result, p)
			seen[p.Address] = true
		}
	}

	// Then DNS peers (fill in gaps)
	for _, p := range dnsPeers {
		if p.Address != "" && !seen[p.Address] {
			result = append(result, p)
			seen[p.Address] = true
		}
	}

	return result
}

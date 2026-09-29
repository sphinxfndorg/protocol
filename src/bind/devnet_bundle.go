// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/devnet_bundle.go
//
// Devnet PUBLIC bundle: network fetch (joiner side) + seed parsing.
//
// The bundle is the three PUBLIC files a late joiner needs to rebuild block 0
// byte-for-byte (two multisig policies + the pre-signed witness book).
// Fetched over the node's plain TCP wire protocol (length-prefixed
// security.Message envelope). Never reads another node's datadir from disk;
// custody/ keys are never requested (not in core's allowlist).
package bind

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// fetchDevnetBundleFile performs one unauthenticated bundle-file request.
// Ready==false means the bootstrap has not produced the file yet (still
// signing) and the caller retries.
func fetchDevnetBundleFile(seedAddr, file string) (core.DevnetBundleResponse, error) {
	var empty core.DevnetBundleResponse
	reqBytes, err := json.Marshal(core.DevnetBundleRequest{File: file})
	if err != nil {
		return empty, err
	}
	msg := security.Message{Type: "devnet_bundle_request", Data: reqBytes}
	encoded, err := msg.Encode()
	if err != nil {
		return empty, err
	}
	conn, err := net.DialTimeout("tcp", seedAddr, 5*time.Second)
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(encoded)))
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return empty, err
	}
	if _, err := conn.Write(encoded); err != nil {
		return empty, err
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return empty, err
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 || size > 16*1024*1024 {
		return empty, fmt.Errorf("implausible bundle frame size %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return empty, err
	}
	var env security.Message
	if err := json.Unmarshal(data, &env); err != nil {
		return empty, err
	}
	if env.Type != "devnet_bundle_response" {
		return empty, fmt.Errorf("unexpected bundle reply type %q", env.Type)
	}
	var resp core.DevnetBundleResponse
	if err := json.Unmarshal(env.Data, &resp); err != nil {
		return empty, err
	}
	if resp.File != "" && resp.File != file {
		return empty, fmt.Errorf("bundle reply for %q, asked %q", resp.File, file)
	}
	return resp, nil
}

// parseDevnetSeeds splits --seeds into plain TCP dial targets, dropping
// empties and enrtree:// entries (bundle fetch is plain TCP only).
func parseDevnetSeeds(seeds string) []string {
	var out []string
	for _, s := range strings.Split(seeds, ",") {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if strings.Contains(t, "enrtree://") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// EnsureDevnetBundleFromSeeds fetches the PUBLIC bundle for a devnet joiner
// BEFORE AutoProvisionDevnetCustody (hence before the first GetGenesisHash()).
// Retries while the bootstrap is still signing; returns time spent waiting.
// Bootstrap nodes, non-devnet networks, seedless nodes, and nodes whose
// datadir already holds the bundle do nothing. Fetched bytes are verified
// before they touch disk.
func EnsureDevnetBundleFromSeeds(networkType, seeds, dataDir string) (time.Duration, error) {
	return ensureDevnetBundleFromSeeds(networkType, seeds, dataDir)
}

// ensureDevnetBundleFromSeeds fetches the PUBLIC bundle for a devnet joiner
// BEFORE AutoProvisionDevnetCustody (hence before the first GetGenesisHash()).
// Retries while the bootstrap is still signing; returns time spent waiting.
// Bootstrap nodes, non-devnet networks, seedless nodes, and nodes whose
// datadir already holds the bundle do nothing. Fetched bytes are verified
// before they touch disk.
func ensureDevnetBundleFromSeeds(networkType, seeds, dataDir string) (time.Duration, error) {
	start := time.Now()
	if !core.DevnetAutoCustodyRequested(networkType) {
		return 0, nil
	}
	if seeds == "" {
		return 0, nil
	}
	addrs := parseDevnetSeeds(seeds)
	if len(addrs) == 0 {
		return 0, nil
	}
	if dataDir == "" {
		return 0, fmt.Errorf("devnet bundle fetch needs a datadir")
	}
	if core.DevnetBundleComplete(dataDir) {
		logger.Info("DEVNET BUNDLE: local bundle already complete — no fetch, no overwrite")
		return 0, nil
	}
	files := []string{}
	for _, f := range core.DevnetPublicBundleFiles {
		files = append(files, f.Name)
	}
	pending := map[string][]byte{} // nil value = optional file given up on
	attempts := map[string]int{}
	optionalGiveUp := 3 // rounds an optional file may stay missing before we stop asking
	lastLog := time.Now().Add(-time.Hour)
	deadline := start.Add(30 * time.Minute)
	waitedLog := false
	for {
		allDone := true
		for _, name := range files {
			if _, ok := pending[name]; ok {
				continue
			}
			allDone = false
			for _, addr := range addrs {
				resp, err := fetchDevnetBundleFile(addr, name)
				if err != nil {
					continue
				}
				if !resp.Ready || len(resp.Data) == 0 {
					continue
				}
				if err := core.ValidateDevnetBundleBytes(name, resp.Data); err != nil {
					return time.Since(start), fmt.Errorf("fetched %s failed verification: %w", name, err)
				}
				pending[name] = resp.Data
				break
			}
		}
		if allDone {
			break
		}
		if time.Now().After(deadline) {
			return time.Since(start), fmt.Errorf("timed out waiting for the bootstrap bundle")
		}
		// Optional files may legitimately never exist on a network that was not
		// provisioned with `genesis create`. Give up on them after a few rounds
		// instead of blocking the joiner for the whole deadline — but only after
		// actually asking, so a file that merely appears late is still fetched.
		// (After the genesis consolidation nothing in the bundle is optional: the
		// vault policy and witness book live as sections of genesis_state.json,
		// which a joiner cannot rebuild block 0 without.)
		for _, name := range files {
			if _, ok := pending[name]; ok || !core.DevnetBundleOptional(name) {
				continue
			}
			attempts[name]++
			if attempts[name] >= optionalGiveUp {
				pending[name] = nil
				logger.Info("DEVNET BUNDLE: optional file %s not offered by the bootstrap — continuing without it (run `genesis create` on the network to enable it)", name)
			}
		}
		if time.Since(lastLog) >= 15*time.Second {
			logger.Info("DEVNET BUNDLE: waiting for the bootstrap node to finish signing — retrying bundle fetch over the network (elapsed %s)", time.Since(start).Round(time.Second))
			lastLog = time.Now()
			waitedLog = true
		}
		time.Sleep(5 * time.Second)
	}
	for _, name := range files {
		data, ok := pending[name]
		if !ok || data == nil {
			continue // optional file given up on — nothing to write
		}
		subdir, subOK := core.BundleSubdirFor(name)
		if !subOK {
			return time.Since(start), fmt.Errorf("unknown bundle file %q", name)
		}
		if err := core.WriteDevnetBundleFile(dataDir, subdir, data); err != nil {
			return time.Since(start), err
		}
	}
	waited := time.Since(start)
	if waitedLog || waited >= 5*time.Second {
		logger.Info("DEVNET BUNDLE: fetched + verified the public bundle over the network in %s", waited.Round(time.Second))
	} else {
		logger.Info("DEVNET BUNDLE: fetched + verified the public bundle over the network")
	}
	return waited, nil
}

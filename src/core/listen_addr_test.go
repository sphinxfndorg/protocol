// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/listen_addr_test.go
package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sphinxfndorg/protocol/src/params/commit"
)

// chainInfoBlockchain returns a Blockchain with chain params but no listen address.
func chainInfoBlockchain(t *testing.T) *Blockchain {
	t.Helper()
	bc := newMinimalBlockchain(t)
	bc.chainParams = GetDevnetChainParams()
	return bc
}

// TestGetChainInfo_ReportsBoundListenAddr pins the fix: the record names the
// port this node actually bound, not just the chain's default_port parameter.
func TestGetChainInfo_ReportsBoundListenAddr(t *testing.T) {
	bc := chainInfoBlockchain(t)
	bc.SetListenAddr("127.0.0.1:30303")

	info := bc.GetChainInfo()

	if got, want := info["listen_addr"], "127.0.0.1:30303"; got != want {
		t.Errorf("listen_addr = %v, want %q", got, want)
	}
	if got, want := info["p2p_port"], 30303; got != want {
		t.Errorf("p2p_port = %v, want %d", got, want)
	}
}

// TestGetChainInfo_OmitsListenFieldsWhenUnset pins the omitempty contract: a
// Blockchain built without a bound address keeps the exact previous payload
// rather than gaining a misleading p2p_port of 0.
func TestGetChainInfo_OmitsListenFieldsWhenUnset(t *testing.T) {
	info := chainInfoBlockchain(t).GetChainInfo()

	for _, key := range []string{"listen_addr", "p2p_port"} {
		if v, present := info[key]; present {
			t.Errorf("%s present with value %v, want absent", key, v)
		}
	}
}

// TestGetChainInfo_DefaultPortUnchangedByListenAddr guards the constraint that
// this change must not move the persisted chain parameter. default_port keeps
// reporting params.DefaultPort, and that value is still 32309 on devnet and
// 32307 from the commit package.
func TestGetChainInfo_DefaultPortUnchangedByListenAddr(t *testing.T) {
	bc := chainInfoBlockchain(t)
	bc.SetListenAddr("127.0.0.1:30304")
	info := bc.GetChainInfo()

	if got, want := info["default_port"], bc.chainParams.DefaultPort; got != want {
		t.Errorf("default_port = %v, want %d (the chain parameter)", got, want)
	}
	if got, want := bc.chainParams.DefaultPort, 32309; got != want {
		t.Errorf("devnet DefaultPort = %d, want %d", got, want)
	}
	if got, want := int(commit.SphinxChainParams().DefaultPort), 32307; got != want {
		t.Errorf("commit DefaultPort = %d, want %d", got, want)
	}
}

// TestSetListenAddr_UsesBoundAddrNotRequestedAddr is the regression guard: the
// node reports what the kernel granted, so a wildcard host or port 0 can never
// publish the address it merely asked for.
func TestSetListenAddr_UsesBoundAddrNotRequestedAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	bound := ln.Addr().String()
	bc := chainInfoBlockchain(t)
	bc.SetListenAddr(bound)

	if got := bc.GetListenAddr(); got != bound {
		t.Fatalf("GetListenAddr() = %q, want %q", got, bound)
	}

	_, wantPortStr, err := net.SplitHostPort(bound)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", bound, err)
	}
	wantPort, err := strconv.Atoi(wantPortStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", wantPortStr, err)
	}
	if got := bc.GetListenPort(); got != wantPort {
		t.Fatalf("GetListenPort() = %d, want %d", got, wantPort)
	}
	if bc.GetListenPort() == 30303 {
		t.Fatal("GetListenPort() returned the hardcoded CLI default instead of the bound port")
	}
	if got := bc.GetChainInfo()["p2p_port"]; got != wantPort {
		t.Errorf("p2p_port = %v, want %d", got, wantPort)
	}
}

// TestGetListenPort_MalformedAndEmpty pins that an unusable address yields 0,
// which is the signal GetChainInfo uses to omit p2p_port.
func TestGetListenPort_MalformedAndEmpty(t *testing.T) {
	for _, addr := range []string{"", "127.0.0.1", "not-an-addr", "127.0.0.1:not-a-port", "127.0.0.1:0x50"} {
		bc := chainInfoBlockchain(t)
		bc.SetListenAddr(addr)
		if got := bc.GetListenPort(); got != 0 {
			t.Errorf("GetListenPort() for %q = %d, want 0", addr, got)
		}
	}
}

// TestSetListenAddr_ConcurrentWithChainInfo exercises the listenAddr lock: a
// node registers its bound address while readers build the chain-info record.
// Run under -race to be meaningful.
func TestSetListenAddr_ConcurrentWithChainInfo(t *testing.T) {
	bc := chainInfoBlockchain(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			bc.SetListenAddr("127.0.0.1:" + strconv.Itoa(30303+i))
		}(i)
		go func() {
			defer wg.Done()
			for range bc.GetChainInfo() {
			}
			_ = bc.GetListenAddr()
			_ = bc.GetListenPort()
		}()
	}
	wg.Wait()

	if addr := bc.GetListenAddr(); addr == "" {
		t.Fatal("GetListenAddr() empty after concurrent writes")
	}
}

// TestConsensusDigest_ProjectsExactFieldSet pins the genesis commitment's field
// set exactly, so a port can never be added to it silently.
//
// GenesisChainParams is asserted by reflection because it is an exported type.
// The ConsensusDigest projection is an anonymous struct literal inside a
// function, so it has no name to reflect on; it is read out of the AST instead.
// Both lists are spelled out in full on purpose: a substring search for "port"
// would not notice a new field under any other name.
func TestConsensusDigest_ProjectsExactFieldSet(t *testing.T) {
	wantChainParams := []string{"chain_id", "network", "epoch_blocks", "min_stake_nspx"}
	if got := jsonTagsOf(reflect.TypeOf(GenesisChainParams{})); !reflect.DeepEqual(got, wantChainParams) {
		t.Errorf("GenesisChainParams fields = %v, want %v", got, wantChainParams)
	}

	wantProjection := []string{
		"version", "chain_id", "chain", "validators", "funded_accounts",
		"multisig", "escrow_multisig", "witnesses", "bootstrap",
	}
	if got := consensusDigestProjectionTags(t); !reflect.DeepEqual(got, wantProjection) {
		t.Errorf("ConsensusDigest projection fields = %v, want %v", got, wantProjection)
	}
}

// jsonTagsOf returns a struct type's json tag names, minus any ",omitempty".
func jsonTagsOf(t reflect.Type) []string {
	tags := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		tags = append(tags, name)
	}
	return tags
}

// consensusDigestProjectionTags reads the json tags of the anonymous struct that
// ConsensusDigest marshals, straight out of this file's AST.
func consensusDigestProjectionTags(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "genesis.go", nil, 0)
	if err != nil {
		t.Fatalf("parse genesis.go: %v", err)
	}

	var tags []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ConsensusDigest" {
			return true
		}
		ast.Inspect(fn, func(inner ast.Node) bool {
			lit, ok := inner.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := lit.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range typ.Fields.List {
				if field.Tag == nil {
					continue
				}
				unquoted, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					t.Fatalf("unquote tag %s: %v", field.Tag.Value, err)
				}
				spec, ok := strings.CutPrefix(unquoted, "json:")
				if !ok {
					continue
				}
				name, _, _ := strings.Cut(strings.Trim(spec, `"`), ",")
				tags = append(tags, name)
			}
			return false
		})
		return false
	})

	if len(tags) == 0 {
		t.Fatal("no struct literal found in ConsensusDigest")
	}
	return tags
}

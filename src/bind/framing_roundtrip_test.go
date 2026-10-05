// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/framing_roundtrip_test.go
//
// Exercises the REAL serve-then-fetch path for a get_blocks reply over a real
// TCP socket, at the size a multi-block reply actually reaches.
package bind

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// TestGetBlocksReply_RoundTripsAttestationSignatures is the end-to-end check
// that the transport preserves attestation signatures. A committed block's
// attestation is ~4864 bytes; three attestations on three blocks is ~120KB.
// If any layer of the serve path truncates that, the syncing node sees an
// empty signature and fails with "decode signed proof: EOF".
func TestGetBlocksReply_RoundTripsAttestationSignatures(t *testing.T) {
	// Build a reply of 3 blocks x 3 attestations with real signature sizes.
	sig := make([]byte, 4864)
	for i := range sig {
		sig[i] = byte(i % 251)
	}
	blocks := make([]*types.Block, 0, 3)
	for h := uint64(3); h <= 5; h++ {
		blk := &types.Block{
			Header: &types.BlockHeader{Height: h},
		}
		for a := 0; a < 3; a++ {
			blk.Body.Attestations = append(blk.Body.Attestations, &types.Attestation{
				ValidatorID: "Node-a",
				Signature:   sig,
				Height:      h,
				View:        h,
			})
		}
		blocks = append(blocks, blk)
	}

	resp := GetBlocksResponse{Blocks: blocks, TipHeight: 7, ChainReady: true}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("get_blocks reply is %d bytes", len(respBytes))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	served := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		msg := security.Message{Type: "get_blocks", Data: respBytes}
		enc, err := msg.Encode()
		if err != nil {
			served <- err
			return
		}
		served <- writeFramedMessage(c, enc)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	frame, err := readFramedMessageWithTimeout(conn, 30*time.Second)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("serve failed: %v", err)
	}

	var msg security.Message
	if err := json.Unmarshal(frame, &msg); err != nil {
		t.Fatal(err)
	}
	var got GetBlocksResponse
	if err := json.Unmarshal(msg.Data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Blocks) != 3 {
		t.Fatalf("got %d blocks, want 3", len(got.Blocks))
	}
	for _, blk := range got.Blocks {
		for i, att := range blk.Body.Attestations {
			if len(att.Signature) != 4864 {
				t.Fatalf("block %d attestation %d: signature is %d bytes, want 4864 "+
					"(transport truncated the reply)", blk.GetHeight(), i, len(att.Signature))
			}
		}
	}
}

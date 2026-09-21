// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

type stubCall struct {
	method string
	params []interface{}
}

type stubClient struct {
	calls []stubCall
	nonce uint64
	txid  string

	// standard is reported by getcontract as the deployed ContractMeta standard;
	// empty means getcontract fails the way the node fails for an address with
	// no contract stored at it.
	standard string
	// nullContract makes getcontract answer a bare null instead of erroring,
	// modelling the defensive "miss rendered as a null body" case.
	nullContract bool
	// storage maps a contract storage key to its plain-text value, hex-encoded
	// on the wire the way the node's getcontractstorage answers.
	storage map[string]string
	// receipts queues gettransactionreceipt responses, consumed in order; the
	// last one repeats, so a single pending response models "still in flight".
	receipts []string

	// eventResponses maps txid to a JSON-encoded array of events returned
	// by gettransactionevents.
	eventResponses map[string]string
	// blockCount is the tip height reported by getblockcount.
	blockCount uint64
	// blocksByHeight stores full block JSON for getblockbynumber queries.
	blocksByHeight map[uint64]string
}

func (c *stubClient) CallRPC(nodeAddr, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error) {
	paramList, _ := params.([]interface{})
	if paramList == nil {
		paramList = []interface{}{}
	}
	c.calls = append(c.calls, stubCall{method: method, params: paramList})
	switch method {
	case "getnonce":
		return json.RawMessage(fmt.Sprintf("%d", c.nonce)), nil
	case "sendrawtransaction":
		return json.RawMessage(fmt.Sprintf(`{"txid":%q}`, c.txid)), nil
	case "getcontract":
		if c.nullContract {
			return json.RawMessage("null"), nil
		}
		if c.standard == "" {
			return nil, errors.New("stub: no contract registered at the requested address")
		}
		return json.RawMessage(fmt.Sprintf(`{"meta":{"standard":%q}}`, c.standard)), nil
	case "getcontractstorage":
		key := ""
		if len(paramList) > 1 {
			key, _ = paramList[1].(string)
		}
		value, found := c.storage[key]
		if !found {
			return nil, fmt.Errorf("contract storage key %q not found", key)
		}
		return json.RawMessage(fmt.Sprintf("%q", "0x"+hex.EncodeToString([]byte(value)))), nil
	case "gettransactionreceipt":
		if len(c.receipts) == 0 {
			return nil, errors.New("stub: no receipt queued")
		}
		raw := c.receipts[0]
		if len(c.receipts) > 1 {
			c.receipts = c.receipts[1:]
		}
		return json.RawMessage(raw), nil
	case "gettransactionevents":
		key := ""
		if len(paramList) > 0 {
			key, _ = paramList[0].(string)
		}
		if c.eventResponses == nil {
			return nil, fmt.Errorf("stub: unknown txid %q", key)
		}
		eventsJSON, ok := c.eventResponses[key]
		if !ok {
			return nil, fmt.Errorf("stub: unknown txid %q", key)
		}
		return json.RawMessage(eventsJSON), nil
	case "getblockcount":
		return json.RawMessage(fmt.Sprintf("%d", c.blockCount)), nil
	case "getblockbynumber":
		height := uint64(0)
		if len(paramList) > 0 {
			if h, ok := paramList[0].(float64); ok {
				height = uint64(h)
			}
		}
		if c.blocksByHeight == nil {
			return nil, fmt.Errorf("stub: block %d not found", height)
		}
		blockJSONStr, found := c.blocksByHeight[height]
		if !found {
			return nil, fmt.Errorf("stub: block %d not found", height)
		}
		return json.RawMessage(blockJSONStr), nil
	default:
		return nil, fmt.Errorf("unexpected method %s", method)
	}
}

type stubSigner struct{ signed int }

func (s *stubSigner) SignTransaction(tx *types.Transaction) error {
	s.signed++
	tx.Signature = []byte{0xAA}
	tx.SignatureHash = make([]byte, 32)
	tx.PublicKey = []byte{0xBB}
	return nil
}

// methods lists the RPC methods the stub was asked for, in order.
func (c *stubClient) methods() []string {
	out := make([]string, 0, len(c.calls))
	for _, call := range c.calls {
		out = append(out, call.method)
	}
	return out
}

func (c *stubClient) broadcast(t *testing.T) *types.Transaction {
	t.Helper()
	if len(c.calls) == 0 {
		t.Fatal("no RPC calls recorded")
	}
	last := c.calls[len(c.calls)-1]
	if last.method != "sendrawtransaction" {
		t.Fatalf("last call = %s, want sendrawtransaction", last.method)
	}
	raw, ok := last.params[0].(string)
	if !ok {
		t.Fatalf("broadcast payload type = %T, want string", last.params[0])
	}
	data, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("payload is not canonical hex: %v", err)
	}
	var tx types.Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		t.Fatalf("payload is not a canonical transaction: %v", err)
	}
	return &tx
}

func TestTransactSignsEncodesAndBroadcasts(t *testing.T) {
	client := &stubClient{txid: "tx-1"}
	signer := &stubSigner{}
	nonce := uint64(4)
	opts := &TransactOpts{Client: client, Signer: signer, NodeAddr: "127.0.0.1:32307", ChainID: 7331, Nonce: &nonce}

	tx := &types.Transaction{Sender: "alice", ToContract: "SPIF123", CallData: []byte(`{"method":"info"}`)}
	txid, err := Transact(opts, tx)
	if err != nil {
		t.Fatalf("Transact: %v", err)
	}
	if txid != "tx-1" {
		t.Fatalf("txid = %q, want tx-1", txid)
	}
	if signer.signed != 1 {
		t.Fatalf("signer called %d times, want 1", signer.signed)
	}
	if len(client.calls) != 1 {
		t.Fatalf("made %d RPC calls, want 1 (explicit nonce must not re-read getnonce)", len(client.calls))
	}
	broadcast := client.broadcast(t)
	if broadcast.Nonce != nonce {
		t.Fatalf("broadcast nonce = %d, want %d", broadcast.Nonce, nonce)
	}
	if broadcast.ID == "" {
		t.Fatal("transaction ID was not derived before signing")
	}
	if len(broadcast.Signature) == 0 {
		t.Fatal("auth bundle missing from broadcast payload")
	}
}

func TestTransactResolvesNonceWhenUnset(t *testing.T) {
	client := &stubClient{txid: "tx-2", nonce: 9}
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: "127.0.0.1:32307"}

	if _, err := Transact(opts, &types.Transaction{Sender: "alice"}); err != nil {
		t.Fatalf("Transact: %v", err)
	}
	if len(client.calls) != 2 || client.calls[0].method != "getnonce" {
		t.Fatalf("calls = %#v, want getnonce then sendrawtransaction", client.calls)
	}
	if got := client.broadcast(t).Nonce; got != 9 {
		t.Fatalf("broadcast nonce = %d, want 9", got)
	}
}

func TestSIPContractsShareOneTransactPath(t *testing.T) {
	client := &stubClient{txid: "tx-3"}
	nonce := uint64(1)
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: "127.0.0.1:32307", ChainID: 7331, Nonce: &nonce}

	if _, err := (SIP20Contract{Address: "SPIF20"}).Mint(opts, "owner", "alice", "100"); err != nil {
		t.Fatalf("SIP20 Mint: %v", err)
	}
	if _, err := (SIP721Contract{Address: "SPIF721"}).Mint(opts, "owner", "alice", MintTerms{
		TokenURI: "ipfs://cid", MintID: "m1", RoyaltyBPS: 500, UsageFeeNSPX: "7", RoyaltyRecipient: "bob",
	}); err != nil {
		t.Fatalf("SIP721 Mint: %v", err)
	}
	if len(client.calls) != 2 {
		t.Fatalf("made %d RPC calls, want 2 (one per mint)", len(client.calls))
	}
	for _, call := range client.calls {
		if call.method != "sendrawtransaction" {
			t.Fatalf("method = %s, want sendrawtransaction", call.method)
		}
	}

	if decoded := decodeNewCall(t, client.calls[0].params[0].(string), SIP20ABI); decoded.Method != "mint" || decoded.Args["amount"] != "100" {
		t.Fatalf("sip20 calldata = %#v", decoded)
	}
	if decoded := decodeNewCall(t, client.calls[1].params[0].(string), SIP721ABI); decoded.Method != "mint" ||
		decoded.Args["token_uri"] != "ipfs://cid" || decoded.Args["royalty_bps"] != "500" || decoded.Args["royalty_recipient"] != "bob" {
		t.Fatalf("sip721 calldata = %#v", decoded)
	}
}

// Each typed write packs the ABI method and argument names the node's own
// dispatcher reads (contracts.callSIP721), so the binding cannot drift from the
// runtime it calls.
func TestSIP721TypedWritesPackNodeArgumentNames(t *testing.T) {
	client := &stubClient{txid: "tx-w"}
	nonce := uint64(1)
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: "127.0.0.1:32307", ChainID: 7331, Nonce: &nonce}
	contract := SIP721Contract{Address: "SPIF721"}

	calls := []struct {
		label  string
		method string
		run    func() (string, error)
		args   map[string]string
	}{
		{label: "transfer_from", method: "transfer_from", run: func() (string, error) { return contract.TransferFrom(opts, "alice", "alice", "bob", 4) },
			args: map[string]string{"from": "alice", "to": "bob", "token_id": "4"}},
		{label: "approve", method: "approve", run: func() (string, error) { return contract.Approve(opts, "alice", "bob", 4) },
			args: map[string]string{"to": "bob", "token_id": "4"}},
		{label: "list", method: "list", run: func() (string, error) { return contract.List(opts, "alice", 4, "1200") },
			args: map[string]string{"token_id": "4", "price": "1200"}},
		{label: "buy", method: "buy", run: func() (string, error) { return contract.Buy(opts, "alice", 4, "1200") },
			args: map[string]string{"token_id": "4"}},
		{label: "cancel", method: "cancel", run: func() (string, error) { return contract.Cancel(opts, "alice", 4) },
			args: map[string]string{"token_id": "4"}},
		{label: "purchase_license", method: "purchase_license", run: func() (string, error) { return contract.PurchaseLicense(opts, "alice", 4, "bob", "7") },
			args: map[string]string{"token_id": "4", "licensee": "bob"}},
		{label: "purchase_license_without_licensee", method: "purchase_license", run: func() (string, error) { return contract.PurchaseLicense(opts, "alice", 4, "  ", "7") },
			args: map[string]string{"token_id": "4"}},
		{label: "revoke_license", method: "revoke_license", run: func() (string, error) { return contract.RevokeLicense(opts, "alice", 4) },
			args: map[string]string{"token_id": "4"}},
	}
	for _, want := range calls {
		before := len(client.calls)
		txid, err := want.run()
		if err != nil {
			t.Fatalf("%s: %v", want.label, err)
		}
		if txid != "tx-w" {
			t.Fatalf("%s txid = %q, want tx-w", want.label, txid)
		}
		if len(client.calls) != before+1 {
			t.Fatalf("%s made %d RPC calls, want 1", want.label, len(client.calls)-before)
		}
		decoded := decodeNewCall(t, client.calls[before].params[0].(string), SIP721ABI)
		if decoded.Method != want.method {
			t.Fatalf("%s method = %s, want %s", want.label, decoded.Method, want.method)
		}
		for key, value := range want.args {
			if decoded.Args[key] != value {
				t.Fatalf("%s args = %#v, want %s=%q", want.label, decoded.Args, key, value)
			}
		}
		if len(decoded.Args) != len(want.args) {
			t.Fatalf("%s args = %#v, want exactly %#v", want.label, decoded.Args, want.args)
		}
	}
}

func TestSIP20TransferPacksNodeArgumentNames(t *testing.T) {
	client := &stubClient{txid: "tx-20"}
	nonce := uint64(2)
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: "127.0.0.1:32307", ChainID: 7331, Nonce: &nonce}

	if _, err := (SIP20Contract{Address: "SPIF20"}).Transfer(opts, "alice", "bob", "100"); err != nil {
		t.Fatalf("SIP20 Transfer: %v", err)
	}
	decoded := decodeNewCall(t, client.calls[0].params[0].(string), SIP20ABI)
	if decoded.Method != "transfer" || decoded.Args["to"] != "bob" || decoded.Args["amount"] != "100" {
		t.Fatalf("calldata = %#v", decoded)
	}
}

// The unsigned builders must produce the same calldata as the broadcasting
// methods, so a caller that signs elsewhere sends an identical call.
func TestTypedWriteTxBuildersMatchBroadcastCalldata(t *testing.T) {
	options := TxOptions{ChainID: 7331, Sender: "alice"}
	tx, err := (SIP721Contract{Address: "SPIF721"}).TransferFromTx(options, "alice", "bob", 4)
	if err != nil {
		t.Fatalf("TransferFromTx: %v", err)
	}
	call, err := DecodeCall(SIP721ABI, tx.CallData)
	if err != nil {
		t.Fatalf("decode call data: %v", err)
	}
	if call.Method != "transfer_from" || call.Args["from"] != "alice" || call.Args["to"] != "bob" || call.Args["token_id"] != "4" {
		t.Fatalf("calldata = %#v", call)
	}
	if tx.ToContract != "SPIF721" {
		t.Fatalf("ToContract = %q", tx.ToContract)
	}

	tx, err = (SIP20Contract{Address: "SPIF20"}).TransferTx(options, "bob", "5")
	if err != nil {
		t.Fatalf("TransferTx: %v", err)
	}
	call, err = DecodeCall(SIP20ABI, tx.CallData)
	if err != nil {
		t.Fatalf("decode call data: %v", err)
	}
	if call.Method != "transfer" || call.Args["to"] != "bob" || call.Args["amount"] != "5" {
		t.Fatalf("calldata = %#v", call)
	}
}

// decodeNewCall decodes the call data of a broadcast payload against schema.
func decodeNewCall(t *testing.T, raw string, schema Contract) *contracts.CallSpec {
	t.Helper()
	data, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("payload is not canonical hex: %v", err)
	}
	var tx types.Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		t.Fatalf("payload is not a canonical transaction: %v", err)
	}
	call, err := DecodeCall(schema, tx.CallData)
	if err != nil {
		t.Fatalf("decode call data: %v", err)
	}
	return call
}

func TestTransactRequiresSignerAndClient(t *testing.T) {
	tx := &types.Transaction{Sender: "alice"}
	if _, err := Transact(&TransactOpts{Client: &stubClient{}}, tx); err == nil {
		t.Fatal("expected missing signer to fail")
	}
	if _, err := Transact(&TransactOpts{Signer: &stubSigner{}}, tx); err == nil {
		t.Fatal("expected missing client to fail")
	}
}

// Only the two SIP-721 marketplace escrow methods carry value: every other
// writer must keep broadcasting Amount 0, because the runtime escrows
// tx.Amount at the contract and a stray value would fund a call that never
// asked for one.
func TestNonEscrowWritesBroadcastZeroAmount(t *testing.T) {
	client := &stubClient{txid: "tx-zero"}
	nonce := uint64(1)
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Nonce: &nonce}
	c721 := SIP721Contract{Address: "SPIF721"}
	c20 := SIP20Contract{Address: "SPIF20"}

	writers := []struct {
		label string
		run   func() (string, error)
	}{
		{label: "sip721 mint", run: func() (string, error) {
			return c721.Mint(opts, "alice", "bob", MintTerms{TokenURI: "ipfs://cid", MintID: "m1"})
		}},
		{label: "sip721 transfer_from", run: func() (string, error) { return c721.TransferFrom(opts, "alice", "alice", "bob", 4) }},
		{label: "sip721 approve", run: func() (string, error) { return c721.Approve(opts, "alice", "bob", 4) }},
		{label: "sip721 list", run: func() (string, error) { return c721.List(opts, "alice", 4, "1200") }},
		{label: "sip721 cancel", run: func() (string, error) { return c721.Cancel(opts, "alice", 4) }},
		{label: "sip721 revoke_license", run: func() (string, error) { return c721.RevokeLicense(opts, "alice", 4) }},
		{label: "sip20 mint", run: func() (string, error) { return c20.Mint(opts, "alice", "bob", "100") }},
		{label: "sip20 transfer", run: func() (string, error) { return c20.Transfer(opts, "alice", "bob", "5") }},
	}
	for _, writer := range writers {
		t.Run(writer.label, func(t *testing.T) {
			if _, err := writer.run(); err != nil {
				t.Fatalf("%s: %v", writer.label, err)
			}
			if got := client.broadcast(t).Amount; got == nil || got.Sign() != 0 {
				t.Fatalf("%s broadcast amount = %v, want 0", writer.label, got)
			}
		})
	}
	if opts.Amount != nil {
		t.Fatalf("opts.Amount = %v, want nil — a non-escrow write must not set it", opts.Amount)
	}
}

// The escrow must be the exact value the caller passes, down to the broadcast
// payload: contracts.callSIP721 compares it against the stored price/fee and
// rejects anything else.
func TestEscrowWritesBroadcastTheExactAmount(t *testing.T) {
	client := &stubClient{txid: "tx-escrow"}
	nonce := uint64(1)
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Nonce: &nonce}
	contract := SIP721Contract{Address: "SPIF721"}

	if _, err := contract.Buy(opts, "alice", 4, "1200"); err != nil {
		t.Fatalf("Buy: %v", err)
	}
	if got := client.broadcast(t).Amount; got == nil || got.String() != "1200" {
		t.Fatalf("buy escrow = %v, want 1200", got)
	}
	if _, err := contract.PurchaseLicense(opts, "alice", 4, "bob", "7"); err != nil {
		t.Fatalf("PurchaseLicense: %v", err)
	}
	if got := client.broadcast(t).Amount; got == nil || got.String() != "7" {
		t.Fatalf("purchase_license escrow = %v, want 7", got)
	}

	// The unsigned builders carry the same escrow for callers that sign
	// elsewhere.
	buyTx, err := contract.BuyTx(TxOptions{ChainID: 7331, Sender: "alice"}, 4, "1200")
	if err != nil {
		t.Fatalf("BuyTx: %v", err)
	}
	if buyTx.Amount == nil || buyTx.Amount.String() != "1200" {
		t.Fatalf("BuyTx escrow = %v, want 1200", buyTx.Amount)
	}
	licenseTx, err := contract.PurchaseLicenseTx(TxOptions{ChainID: 7331, Sender: "alice"}, 4, "bob", "7")
	if err != nil {
		t.Fatalf("PurchaseLicenseTx: %v", err)
	}
	if licenseTx.Amount == nil || licenseTx.Amount.String() != "7" {
		t.Fatalf("PurchaseLicenseTx escrow = %v, want 7", licenseTx.Amount)
	}

	// The escrow is per-call: it must not leak into the caller's options, so a
	// following non-escrow write stays zero-valued.
	if opts.Amount != nil {
		t.Fatalf("opts.Amount = %v after escrow calls, want nil", opts.Amount)
	}
	if _, err := contract.List(opts, "alice", 4, "1200"); err != nil {
		t.Fatalf("List after escrow calls: %v", err)
	}
	if got := client.broadcast(t).Amount; got == nil || got.Sign() != 0 {
		t.Fatalf("list after escrow calls carried %v, want 0", got)
	}
}

// The escrow change must not pull the read methods onto the write path: they
// still answer from committed state and never broadcast a transaction.
func TestReadMethodsNeverBroadcast(t *testing.T) {
	client := &stubClient{}
	opts := &CallOpts{Client: client, NodeAddr: stubNodeAddr, From: "alice"}
	c721 := SIP721Contract{Address: "SPIF721"}
	c20 := SIP20Contract{Address: "SPIF20"}

	// Each read fails against this stub (it stores nothing), which is fine:
	// the assertion is which RPC methods were used, not the answers.
	_, _ = c721.OwnerOf(opts, 4)
	_, _ = c721.TokenURI(opts, 4)
	_, _ = c721.TokenIDOfMint(opts, "m1")
	_, _ = c721.TermsOf(opts, 4)
	_, _, _ = c721.ListingOf(opts, 4)
	_, _ = c721.Info(opts)
	_, _ = c20.BalanceOf(opts, "alice")
	_, _ = c20.Info(opts)

	methods := client.methods()
	if len(methods) == 0 {
		t.Fatal("reads made no RPC calls")
	}
	for _, method := range methods {
		if method != "getcontractstorage" && method != "getcontract" {
			t.Fatalf("read used %s, want only read RPCs (calls = %v)", method, methods)
		}
	}
}

// An escrow that cannot be represented as a transaction value is rejected
// before any RPC call. Whether the value matches the posted price is the
// contract's decision at consensus, which rejects any mismatch outright.
func TestEscrowMethodsRejectUnusableAmounts(t *testing.T) {
	client := &stubClient{txid: "tx-bad"}
	nonce := uint64(1)
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Nonce: &nonce}
	contract := SIP721Contract{Address: "SPIF721"}

	for _, amount := range []string{"", "   ", "abc", "-5", "1.5"} {
		if _, err := contract.Buy(opts, "alice", 4, amount); err == nil {
			t.Fatalf("Buy with escrow %q = no error", amount)
		}
		if _, err := contract.PurchaseLicense(opts, "alice", 4, "bob", amount); err == nil {
			t.Fatalf("PurchaseLicense with escrow %q = no error", amount)
		}
	}
	if len(client.calls) != 0 {
		t.Fatalf("calls = %#v, want none", client.calls)
	}
}

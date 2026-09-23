package gui

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	"github.com/sphinxfndorg/protocol/src/common"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
	usi "github.com/sphinxfndorg/protocol/src/usi/gui"
)

type Wallet struct {
	Address    string
	Passphrase string
	Client     *usi.WalletClient
}

func CreateWallet(passphrase string) (*Wallet, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, errors.New("passphrase is required")
	}
	kp, err := keys.GenerateKeyPairWithOrg(passphrase, keys.OrgSPIF)
	if err != nil {
		return nil, err
	}
	return &Wallet{Address: kp.Address, Passphrase: passphrase}, nil
}
func UnlockWallet(passphrase string) (*Wallet, error) {
	kp, _, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		return nil, err
	}
	return &Wallet{Address: kp.Address, Passphrase: passphrase}, nil
}
func (w *Wallet) Attach(addr string) { w.Client = usi.NewWalletClient(addr) }

func rawAddress(s string) (string, error) { return common.NormalizeSPIFAddress(s) }
func nspx(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("amount is required")
	}
	f, _, err := big.ParseFloat(s, 10, 256, big.ToNearestEven)
	if err != nil {
		return nil, errors.New("invalid amount")
	}
	out := new(big.Float).Mul(f, big.NewFloat(1e18))
	i, _ := out.Int(nil)
	if i == nil || i.Sign() <= 0 {
		return nil, errors.New("amount must be positive")
	}
	return i, nil
}
func sendGate(syncing bool, peers int, age int64) bool {
	return !syncing && peers > 0 && age >= 0 && age <= 60000
}

type walletRPC struct{}

func (walletRPC) CallRPC(addr, method string, params interface{}, ttl uint16) (json.RawMessage, error) {
	return rpc.CallRPC(addr, method, params, ttl)
}
func sendSPX(w *Wallet, nodeAddr, to, amount string) (string, error) {
	rawFrom, err := rawAddress(w.Address)
	if err != nil {
		return "", err
	}
	rawTo, err := rawAddress(to)
	if err != nil {
		return "", err
	}
	value, err := nspx(amount)
	if err != nil {
		return "", err
	}
	q := policy.GetDefaultPolicyParams().QuoteTransactionGas(0)
	nonce, err := mint.Nonces.Reserve(walletRPC{}, nodeAddr, rawFrom)
	if err != nil {
		return "", err
	}
	tx := &types.Transaction{ChainID: 73310, Sender: rawFrom, Receiver: rawTo, Amount: value,
		GasLimit: q.GasLimit, GasPrice: q.GasPrice, Nonce: nonce, Timestamp: time.Now().Unix()}
	opts := &abi.TransactOpts{Client: walletRPC{}, Signer: mint.KeyFileSigner{KeyFile: w.Passphrase},
		NodeAddr: nodeAddr, ChainID: 73310, Nonce: &nonce, Reserver: mint.Nonces}
	id, err := abi.Transact(opts, tx)
	if err != nil {
		mint.Nonces.Release(nodeAddr, rawFrom, nonce)
		return "", err
	}
	return id, nil
}

// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package utils

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
)

func runMultisigCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("multisig requires a subcommand: devnet, spend, create, message, sign, combine")
	}
	switch args[0] {
	case "devnet":
		return runMultisigDevnet(args[1:])
	case "spend":
		return runMultisigSpend(args[1:])
	case "create":
		return runMultisigCreate(args[1:])
	case "message":
		return runMultisigMessage(args[1:])
	case "sign":
		return runMultisigSign(args[1:])
	case "combine":
		return runMultisigCombine(args[1:])
	default:
		return fmt.Errorf("unknown multisig subcommand %q", args[0])
	}
}

func readHexFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hexStr := firstField(string(data))
	if len(hexStr) > 0 && hexStr[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		hexStr = s
	}
	b, err := hex.DecodeString(stripHexPrefix(hexStr))
	if err != nil {
		return nil, fmt.Errorf("bad hex in %s: %w", path, err)
	}
	return b, nil
}

func stripHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}

func firstField(s string) string {
	for _, f := range splitFields(s) {
		if f != "" {
			return f
		}
	}
	return ""
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	flush := func() {
		if cur != "" {
			out = append(out, cur)
			cur = ""
		}
	}
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			flush()
			continue
		}
		cur += string(r)
	}
	flush()
	return out
}

// defaultCustodyChainID matches core/params.go's mainnet ChainID and is what
// the custody-spend path compares a transaction's ChainID against.
const defaultCustodyChainID uint64 = 7331

// parseAmount reads exactly one of --amount-nspx / --amount-spx.
func parseAmount(nspxStr, spxStr string) (*big.Int, error) {
	if nspxStr == "" && spxStr == "" {
		return nil, nil
	}
	if nspxStr != "" && spxStr != "" {
		return nil, fmt.Errorf("give either --amount-nspx or --amount-spx, not both")
	}
	if nspxStr != "" {
		v, ok := new(big.Int).SetString(strings.TrimSpace(nspxStr), 10)
		if !ok || v.Sign() < 0 {
			return nil, fmt.Errorf("bad --amount-nspx %q: expected a non-negative decimal integer", nspxStr)
		}
		return v, nil
	}
	v, ok := new(big.Int).SetString(strings.TrimSpace(spxStr), 10)
	if !ok || v.Sign() < 0 {
		return nil, fmt.Errorf("bad --amount-spx %q: expected a non-negative decimal integer", spxStr)
	}
	return v.Mul(v, big.NewInt(1e18)), nil
}

// runMultisigMessage builds the exact message a custodian must sign, using the
// same policy, domain, chain ID and canonical encoder the verifier uses. It is
// the operator-facing counterpart of musig.SpendMessage /
// CustodyReleaseMessage / DevModuleReleaseMessage: custodians never
// hand-compute the bytes, and a drift between signer and verifier is
// impossible because both call the same function.
//
//	multisig message --policy vault.json --kind spend \
//	    --receiver <addr> --amount-spx 1000 --nonce 0 --expiry <unix> \
//	    --release-time <unix> --out spend.msg
func runMultisigMessage(args []string) error {
	fs := flag.NewFlagSet("multisig message", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy JSON file (supplies the domain and the custodial address)")
	kind := fs.String("kind", "spend", "spend | cge-release | dev-module")
	sender := fs.String("sender", "", "custodial source address (default: the policy's derived address)")
	receiver := fs.String("receiver", "", "destination address")
	amountNSPX := fs.String("amount-nspx", "", "exact amount in nSPX (decimal)")
	amountSPX := fs.String("amount-spx", "", "amount in whole SPX (decimal)")
	nonce := fs.Uint64("nonce", 0, "account nonce (spend) / block height (cge-release) / module id (dev-module)")
	expiry := fs.Uint64("expiry", 0, "witness expiry as a unix timestamp")
	chainID := fs.Uint64("chain-id", defaultCustodyChainID, "chain id bound into the message")
	releaseTime := fs.Uint64("release-time", 0, "expected release unix timestamp for the expiry-horizon check (0 = skip)")
	out := fs.String("out", "", "output file holding the message to sign")
	asHex := fs.Bool("hex", false, "write the message as hex text instead of raw bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" || *receiver == "" || *out == "" {
		return fmt.Errorf("--policy, --receiver and --out are required")
	}
	p, err := multisig.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}
	from := *sender
	if from == "" {
		from, err = p.Address()
		if err != nil {
			return err
		}
	}
	if err := multisig.ValidateWitnessExpiry(*expiry, *releaseTime); err != nil {
		return err
	}
	amount, err := parseAmount(*amountNSPX, *amountSPX)
	if err != nil {
		return err
	}

	var msg []byte
	switch *kind {
	case "spend":
		if amount == nil {
			return fmt.Errorf("--kind spend requires --amount-nspx or --amount-spx")
		}
		msg = multisig.SpendMessage(p, *chainID, from, *receiver, amount, *nonce, *expiry)
	case "cge-release":
		if amount == nil {
			return fmt.Errorf("--kind cge-release requires --amount-nspx or --amount-spx")
		}
		msg = multisig.CustodyReleaseMessage(p.Domain, *chainID, from, *receiver, amount.Bytes(), *nonce, *expiry)
	case "dev-module":
		msg = multisig.DevModuleReleaseMessage(p.Domain, *chainID, from, *receiver, *nonce, *expiry)
	default:
		return fmt.Errorf("unknown --kind %q (want spend, cge-release or dev-module)", *kind)
	}

	payload := msg
	if *asHex {
		payload = []byte(hex.EncodeToString(msg))
	}
	if err := os.WriteFile(*out, payload, 0600); err != nil {
		return err
	}

	fmt.Printf("kind:      %s\n", *kind)
	fmt.Printf("domain:    %s\n", p.Domain)
	fmt.Printf("chain id:  %d\n", *chainID)
	fmt.Printf("from:      %s\n", from)
	fmt.Printf("to:        %s\n", *receiver)
	if amount != nil {
		fmt.Printf("amount:    %s nSPX\n", amount.String())
	}
	fmt.Printf("nonce:     %d\n", *nonce)
	fmt.Printf("expiry:    %d\n", *expiry)
	fmt.Printf("message:   %s\n", hex.EncodeToString(msg))
	fmt.Printf("written:   %s\n", *out)
	signCmd := fmt.Sprintf("multisig sign --policy %s --tx %s", *policyPath, *out)
	if *asHex {
		signCmd += " --hex"
	}
	fmt.Printf("sign with: %s --key <your-key-file>\n", signCmd)
	return nil
}

func runMultisigSign(args []string) error {
	fs := flag.NewFlagSet("multisig sign", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy JSON file")
	txPath := fs.String("tx", "", "message file to sign")
	keyFile := fs.String("key", "", "signing key file")
	out := fs.String("out", "", "output partial-sig file")
	txHex := fs.Bool("hex", false, "treat --tx as a hex-text message (as written by 'multisig message --hex')")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" || *txPath == "" || *keyFile == "" {
		return fmt.Errorf("--policy, --tx and --key are required")
	}
	p, err := multisig.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}
	msg, err := os.ReadFile(*txPath)
	if err != nil {
		return err
	}
	if *txHex {
		msg, err = hex.DecodeString(stripHexPrefix(firstField(string(msg))))
		if err != nil {
			return fmt.Errorf("bad hex message in %s: %w", *txPath, err)
		}
	}
	skBytes, pkBytes, err := loadSigningKeyFile(*keyFile)
	if err != nil {
		return err
	}
	found := -1
	for i, pk := range p.PubKeys {
		if hex.EncodeToString(pk) == hex.EncodeToString(pkBytes) {
			found = i
			break
		}
	}
	if found < 0 {
		return fmt.Errorf("local pubkey is not a custodian in this policy")
	}
	sig, err := multisig.SignCustodyMessage(msg, skBytes, pkBytes)
	if err != nil {
		return err
	}
	obj := map[string]string{"index": strconv.Itoa(found), "sig": hex.EncodeToString(sig)}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, data, 0644); err != nil {
			return err
		}
	}
	fmt.Printf("%s\n", string(data))
	return nil
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return fmt.Sprintf("%v", *s) }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runMultisigCreate(args []string) error {
	fs := flag.NewFlagSet("multisig create", flag.ContinueOnError)
	var pubs stringSliceFlag
	threshold := fs.Int("threshold", 0, "M in M-of-N")
	domain := fs.String("domain", "", "domain separation string")
	out := fs.String("out", "", "output policy file")
	fs.Var(&pubs, "pubkey", "hex pubkey file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pubs = append(pubs, fs.Args()...)
	if *domain == "" {
		return fmt.Errorf("--domain is required")
	}
	if *threshold <= 0 {
		return fmt.Errorf("--threshold is required")
	}
	if len(pubs) == 0 {
		return fmt.Errorf("at least one --pubkey file is required")
	}
	p := &multisig.MultiPartyPolicy{Threshold: uint8(*threshold), Domain: *domain}
	for _, f := range pubs {
		b, err := readHexFile(f)
		if err != nil {
			return err
		}
		p.PubKeys = append(p.PubKeys, b)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	addr, err := p.Address()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, data, 0644); err != nil {
			return err
		}
	}
	fmt.Printf("address: %s\n%s\n", addr, string(data))
	return nil
}

func runMultisigCombine(args []string) error {
	fs := flag.NewFlagSet("multisig combine", flag.ContinueOnError)
	var sigs stringSliceFlag
	policyPath := fs.String("policy", "", "policy JSON file")
	expiry := fs.Uint64("expiry", 0, "witness expiry as a unix timestamp (must be generous enough to cover the whole vesting release)")
	releaseTime := fs.Uint64("release-time", 0, "expected release unix timestamp, for the expiry-horizon check (0 = skip)")
	out := fs.String("out", "", "output witness file")
	fs.Var(&sigs, "sig", "partial-sig JSON file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sigs = append(sigs, fs.Args()...)
	if *policyPath == "" {
		return fmt.Errorf("--policy is required")
	}
	if len(sigs) == 0 {
		return fmt.Errorf("at least one --sig file is required")
	}
	if err := multisig.ValidateWitnessExpiry(*expiry, *releaseTime); err != nil {
		return err
	}
	p, err := multisig.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}
	w := multisig.MultiSigWitness{Policy: *p, Sigs: map[int][]byte{}, Expiry: *expiry}
	for _, f := range sigs {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var obj map[string]string
		if err := json.Unmarshal(data, &obj); err != nil {
			return fmt.Errorf("bad sig file %s: %w", f, err)
		}
		idx, err := strconv.Atoi(obj["index"])
		if err != nil {
			return fmt.Errorf("bad index in %s: %w", f, err)
		}
		sb, err := hex.DecodeString(obj["sig"])
		if err != nil {
			return fmt.Errorf("bad sig in %s: %w", f, err)
		}
		w.Sigs[idx] = sb
	}
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, data, 0644); err != nil {
			return err
		}
	}
	fmt.Printf("threshold_met=%v sigs=%d threshold=%d expiry=%d\n%s\n",
		w.MeetsThreshold(), len(w.Sigs), p.Threshold, w.Expiry, string(data))
	return nil
}

// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/sphinxfndorg/protocol/src/common"
)

type MultiPartyPolicy struct {
	PubKeys   [][]byte `json:"-"`
	Threshold uint8    `json:"threshold"`
	Domain    string   `json:"domain"`
}

type jsonPolicy struct {
	PubKeys   []string `json:"pubkeys"`
	Threshold uint8    `json:"threshold"`
	Domain    string   `json:"domain"`
}

func (p *MultiPartyPolicy) Validate() error {
	if p == nil {
		return fmt.Errorf("nil policy")
	}
	if len(p.PubKeys) == 0 {
		return fmt.Errorf("policy has no pubkeys")
	}
	if p.Threshold == 0 {
		return fmt.Errorf("threshold must be >= 1")
	}
	if int(p.Threshold) > len(p.PubKeys) {
		return fmt.Errorf("threshold %d exceeds %d custodians", p.Threshold, len(p.PubKeys))
	}
	if p.Domain == "" {
		return fmt.Errorf("domain must be non-empty")
	}
	for i, pk := range p.PubKeys {
		if len(pk) == 0 {
			return fmt.Errorf("pubkey[%d] is empty", i)
		}
	}
	return nil
}

func sortedKeys(pks [][]byte) [][]byte {
	out := make([][]byte, len(pks))
	copy(out, pks)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func (p *MultiPartyPolicy) Address() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	buf := make([]byte, 0, 64)
	buf = append(buf, []byte(p.Domain)...)
	buf = append(buf, 0x00, p.Threshold, byte(len(p.PubKeys)))
	for _, pk := range sortedKeys(p.PubKeys) {
		buf = append(buf, byte(len(pk)>>8), byte(len(pk)))
		buf = append(buf, pk...)
	}
	digest := common.SpxHash(buf)
	return fmt.Sprintf("%X", digest[:20]), nil
}

func (p MultiPartyPolicy) MarshalJSON() ([]byte, error) {
	jp := jsonPolicy{Threshold: p.Threshold, Domain: p.Domain}
	for _, pk := range p.PubKeys {
		jp.PubKeys = append(jp.PubKeys, hex.EncodeToString(pk))
	}
	return json.Marshal(jp)
}

func (p *MultiPartyPolicy) UnmarshalJSON(data []byte) error {
	var jp jsonPolicy
	if err := json.Unmarshal(data, &jp); err != nil {
		return err
	}
	p.Threshold = jp.Threshold
	p.Domain = jp.Domain
	p.PubKeys = make([][]byte, 0, len(jp.PubKeys))
	for i, s := range jp.PubKeys {
		b, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("pubkeys[%d]: %w", i, err)
		}
		p.PubKeys = append(p.PubKeys, b)
	}
	return p.Validate()
}

func LoadPolicy(path string) (*MultiPartyPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p MultiPartyPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *MultiPartyPolicy) Save(path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

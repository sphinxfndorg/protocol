// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/json"
	"testing"

	"github.com/sphinxfndorg/protocol/src/core"
)

func TestAnchorJSONShowsGroupedRoyaltyRecipient(t *testing.T) {
	receipt := mintTestReceipt("bafkqaccd1234abcd1234abcd1234abcd")
	receipt.TokenID = 1
	receipt.TokenURI = "ipfs://bafkreid5w7jk7octbp54tur24isnzjb7v4mo4ehmauyhd4dt5t6jzkxzsu"
	receipt.ContractAddress = "SPIF E08E 9047 212D CA37 C89E B8E5 0838 5CD5 A466 98FD D21E 98F0 5648 038C E193 BFF0"
	receipt.RoyaltyBPS = 500
	receipt.UsageFeeNSPX = "10000000000000000000"
	// Exactly the value from the reported bad anchor JSON (raw hex blob).
	receipt.RoyaltyRecipient = "F6F666A0F07BB9F1B9C36C0BC497DEF789ACA6B4A7564F88A6277FCBBFD909F8"

	data, err := BuildAnchorData(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.ValidateAnchorData(data); err != nil {
		t.Fatalf("node rejected formatted anchor: %v", err)
	}
	t.Logf("anchor JSON:\n%s", data)
	var tag AnchorTag
	if err := json.Unmarshal(data, &tag); err != nil {
		t.Fatal(err)
	}
	if tag.RoyaltyRecipient != "SPIF F6F6 66A0 F07B B9F1 B9C3 6C0B C497 DEF7 89AC A6B4 A756 4F88 A627 7FCB BFD9 09F8" {
		t.Fatalf("recipient not in grouped SPIF form: %q", tag.RoyaltyRecipient)
	}
	if ok, err := VerifyAnchor(receipt, data); !ok || err != nil {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
}

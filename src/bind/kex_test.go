package bind

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/sphinxfndorg/protocol/src/core"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

func TestValidatePeerGenesisHash(t *testing.T) {
	tests := []struct {
		name  string
		peer  string
		local string
		want  bool
	}{
		{name: "matching", peer: "genesis-a", local: "genesis-a", want: true},
		{name: "missing peer hash", peer: "", local: "genesis-a", want: false},
		{name: "missing local hash", peer: "genesis-a", local: "", want: false},
		{name: "mismatch", peer: "genesis-a", local: "genesis-b", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePeerGenesisHash(tt.peer, tt.local)
			if (err == nil) != tt.want {
				t.Fatalf("validatePeerGenesisHash(%q, %q) error = %v, want success=%v", tt.peer, tt.local, err, tt.want)
			}
		})
	}
}

func TestIncomingKeyExchangeRejectsGenesisMismatchBeforeAdmission(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	var discovered, stakeClaim bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleIncomingConn(
			server, "self", "127.0.0.1:1", "", nil, nil, nil, nil, nil, nil, nil,
			func(string, string) { discovered = true },
			func(string, string) { stakeClaim = true },
		)
	}()

	data, err := json.Marshal(peerKeyExchangeMsg{
		NodeID:      "attacker",
		GenesisHash: "definitely-not-" + core.GetGenesisHash(),
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := security.Message{Type: "key_exchange", Data: data}
	msg, err := envelope.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFramedMessage(client, msg); err != nil {
		t.Fatal(err)
	}
	<-done

	if discovered || stakeClaim {
		t.Fatalf("mismatched key exchange triggered admission side effects: discovered=%v stakeClaim=%v", discovered, stakeClaim)
	}
}

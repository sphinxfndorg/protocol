package utils

import (
	"os"
	"strings"
	"testing"
)

func TestGenesisSubcommandIsNotAvailable(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"sphinx", "genesis"}

	err := Execute()
	if err == nil || !strings.Contains(err.Error(), `unknown subcommand "genesis"`) {
		t.Fatalf("Execute() error = %v, want unknown genesis subcommand", err)
	}
}

func TestStakeSubcommandRequiresValidatorIdentityKey(t *testing.T) {
	err := runStakeCmd([]string{
		"--action=stake",
		"--from=SPIF",
		"--validator-id=Node-test",
		"--key=wallet.json",
	})
	if err == nil || !strings.Contains(err.Error(), "--validator-key is required") {
		t.Fatalf("runStakeCmd() error = %v, want missing validator-key error", err)
	}
}

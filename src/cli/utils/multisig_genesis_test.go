package utils

import (
	"path/filepath"
	"testing"

	"github.com/sphinxfndorg/protocol/src/core"
)

func TestDirOfGenesisDoc(t *testing.T) {
	absoluteDatadir := t.TempDir()
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "relative default", path: core.GenesisStateFileSubdir, want: ""},
		{name: "datadir path", path: filepath.Join("data", "node1", core.GenesisStateFileSubdir), want: filepath.Join("data", "node1")},
		{name: "absolute path", path: filepath.Join(absoluteDatadir, core.GenesisStateFileSubdir), want: absoluteDatadir},
		{name: "other file", path: "config/escrow-policy.json", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := dirOfGenesisDoc(test.path)
			if (err != nil) != test.wantErr {
				t.Fatalf("dirOfGenesisDoc(%q) error = %v", test.path, err)
			}
			if err == nil && got != test.want {
				t.Fatalf("dirOfGenesisDoc(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

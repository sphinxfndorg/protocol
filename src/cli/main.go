// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/main.go
package main

import (
	"log"
	"os"

	cli "github.com/sphinxfndorg/protocol/src/cli/utils"
)

func main() {
	if err := cli.Execute(); err != nil {
		log.Printf("CLI execution failed: %v", err)
		os.Exit(1)
	}
}

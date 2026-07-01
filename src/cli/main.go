// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/main.go
package main

import (
	"github.com/sphinxfndorg/protocol/src/cli/utils"
)

func main() {
	if err := utils.Execute(); err != nil {
		panic(err)
	}
}
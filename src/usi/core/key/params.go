// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/params.go
package keys

import "github.com/kasperdi/SPHINCSPLUS-golang/parameters"

// DefaultParams uses SHAKE256-128f-robust with randomization enabled
var DefaultParams = parameters.MakeSphincsPlusSHAKE256128fRobust(true)

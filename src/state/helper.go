// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/state/interface.go
package state

// Ensure Storage implements BlockStorage
var _ BlockStorage = (*Storage)(nil)

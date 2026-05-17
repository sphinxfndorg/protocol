// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/account/key/utils/types.go
package utils

import (
	disk "github.com/sphinxorg/protocol/src/accounts/key/disk"
	usb "github.com/sphinxorg/protocol/src/accounts/key/external"
)

// StorageType represents the type of storage
type StorageType string

const (
	StorageTypeDisk StorageType = "disk"
	StorageTypeUSB  StorageType = "usb"
)

// StorageManager manages multiple storage types
type StorageManager struct {
	diskStore *disk.DiskKeyStore
	usbStore  *usb.USBKeyStore
}

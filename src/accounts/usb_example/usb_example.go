// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package main

import (
	"fmt"
	"log"

	utils "github.com/sphinxorg/protocol/src/accounts/key/utils"
)

// CONTEXT: this is a separate demo from test_encrypt.go. test_encrypt.go
// only ever talks to diskStorage — it never touches USBKeyStore. This file
// shows the disk -> USB -> disk path using the StorageManager methods that
// already exist in utils.go (BackupToUSB / RestoreFromUSB), which wrap
// USBKeyStore.BackupFromDisk / RestoreToDisk under the hood.
//
// IMPORTANT CLARIFICATION: "USB keystore" here means a removable USB drive
// used as offline file storage for encrypted key blobs — it is NOT the same
// thing as a Ledger or other hardware wallet. A Ledger generates keys
// on-device, never exposes the raw private key outside its secure element,
// and signs transactions on-chip. This USBKeyStore just copies the same
// AES-256-GCM-encrypted JSON blobs DiskKeyStore already produces onto a
// different filesystem path. The keys are still fully decrypted in this
// program's memory whenever you call DecryptKey — the USB drive buys you
// "offline / removable backup," not "key never leaves secure hardware."
//
// NOTE ON BackupFromDisk's passphrase parameter: looking at usb.go,
// BackupFromDisk(diskStore, passphrase) takes a passphrase argument but
// doesn't actually use it to re-encrypt anything — it copies the
// already-encrypted KeyPair.EncryptedSK blobs from disk to USB as-is via
// json.MarshalIndent, and the passphrase only ends up in the backup
// manifest as a boolean ("encrypted": passphrase != ""). That's fine
// functionally (the blobs are already AES-GCM ciphertext, so copying them
// verbatim is safe), but worth knowing: passing a passphrase here does NOT
// add a second layer of encryption, despite what the parameter name might
// suggest.
func main() {
	storageManager, err := utils.NewStorageManager()
	if err != nil {
		log.Fatal("Failed to initialize storage manager:", err)
	}

	// --- 1. Point at the USB device's mount path ---
	// Replace with your actual mounted USB path, e.g. "/Volumes/MYUSB" on
	// macOS or "/media/<user>/<label>" on Linux. The path must already be a
	// mounted, writable volume — this does not mount the device for you.
	usbPath := "/Volumes/MYUSB" // CHANGE ME before running

	// --- 2. Initialize the USB volume as a Sphinx keystore (first time only) ---
	// Creates sphinx-usb-keystore/{keys,backup}/ and a usb-info.json marker
	// at usbPath. Safe to call again on an already-initialized volume —
	// MkdirAll is a no-op if the directories already exist, though it will
	// overwrite usb-info.json's created_at each time. Skip this call on
	// subsequent runs against the same drive if you don't want that.
	if err := storageManager.InitializeUSBStorage(usbPath); err != nil {
		log.Fatalf("Failed to initialize USB keystore: %v", err)
	}

	// --- 3. Mount it ---
	// Mount() (called via MountUSB) verifies usbPath exists and contains a
	// sphinx-usb-keystore directory, then loads any existing keys from it
	// into memory. This is a logical "mount" (marking ks.isMounted = true
	// and loading key files) — it doesn't touch OS-level volume mounting,
	// which must already have happened (the drive must already show up in
	// your filesystem) before this call.
	if err := storageManager.MountUSB(usbPath); err != nil {
		log.Fatalf("Failed to mount USB keystore: %v", err)
	}
	defer storageManager.UnmountUSB()

	fmt.Println("USB keystore mounted at:", usbPath)

	// --- 4. Back up every key currently in the disk keystore to USB ---
	// Internally: StorageManager.BackupToUSB -> USBKeyStore.BackupFromDisk
	// -> lists all disk keys, writes each one's already-encrypted JSON blob
	// into a timestamped backup/<timestamp>/ directory on the USB drive,
	// plus a backup-manifest.json. See the note above about the passphrase
	// argument's actual (non-)effect.
	if err := storageManager.BackupToUSB(""); err != nil {
		log.Fatalf("Failed to back up disk keys to USB: %v", err)
	}
	fmt.Println("Backed up all disk keys to USB.")

	// --- 5. Restore from USB back into the disk keystore ---
	//
	// FIXED: BackupFromDisk now writes keys into "<mountPath>/keys/" (the
	// directory ListKeys()/RestoreToDisk() actually read from), in addition
	// to the timestamped "<mountPath>/backup/<timestamp>/" audit copy it
	// always wrote. Previously these were two non-overlapping locations and
	// a restore right after a backup would silently return 0 keys — see
	// usb.go's updated BackupFromDisk doc comment for the full history.
	// With the fix, this restore step should now report the same count of
	// keys that were backed up in step 4.
	restoredCount, err := storageManager.RestoreFromUSB("")
	if err != nil {
		log.Fatalf("Failed to restore keys from USB: %v", err)
	}
	fmt.Printf("Restored %d key(s) from USB.\n", restoredCount)

	info := storageManager.GetStorageInfo()
	fmt.Printf("Disk keystore: %+v\n", info["disk"])
	fmt.Printf("USB keystore:  %+v\n", info["usb"])
}

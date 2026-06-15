// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/config.go
package keys

import "path/filepath"

const (
	KeyRootDir = "./keys"

	// SPHINCS+ (signing)
	SPHINCSKeyDirName  = "sig"
	SPHINCSKeyFileName = "sphincskey.dat"
	SPHINCSDBName      = "sphincs_db"

	// KEM — merged X25519+Kyber768 hybrid keypair (one blob, one file)
	KEMKeyDirName  = "kem"
	KEMKeyFileName = "kyber768x25519.dat"
	KEMDBName      = "kem_db"

	// Backward compatibility
	SPHINCSFileName = SPHINCSKeyFileName
	KEMFileName     = KEMKeyFileName
)

var (
	// SPHINCS+ paths
	SPHINCSKeyDir  = filepath.Join(KeyRootDir, SPHINCSKeyDirName)
	SPHINCSDatPath = filepath.Join(SPHINCSKeyDir, SPHINCSKeyFileName)
	SPHINCSDBPath  = filepath.Join(SPHINCSKeyDir, SPHINCSDBName)

	// KEM paths — single kem.dat holds the merged X25519+Kyber768 private key blob
	KEMKeyDir  = filepath.Join(KeyRootDir, KEMKeyDirName)
	KEMDatPath = filepath.Join(KEMKeyDir, KEMKeyFileName)
	KEMDBPath  = filepath.Join(KEMKeyDir, KEMDBName)

	// Backward compatibility for existing SPHINCS+ code
	KeyDir  = SPHINCSKeyDir
	DatPath = SPHINCSDatPath
	DBPath  = SPHINCSDBPath
)

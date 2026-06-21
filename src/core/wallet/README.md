# Sphinx wallet key management

How SPHINCS+ key pairs are generated, encrypted, and stored on disk or
backed up to a USB drive in this codebase, and how to actually find and
inspect the files it produces.

> **A note on paths in this README.** The source files we've worked through
> have header comments like `// go/src/account/key/external/usb.go`
> (singular `account`), but commands run against this repo have used
> `src/core/wallet/` and `src/accounts/usbdemo/` (plural `accounts`).
> Confirm your actual module layout with `find . -name "usb.go"` and adjust
> the paths below accordingly — this README uses the plural `accounts/`
> form since that's what's been confirmed working via `go run .`.

## What gets generated

Running the demo at `src/core/wallet/test_encrypt.go` does three things in
sequence:

1. **A SPHINCS+ key pair** (`sk`, `pk`) — the actual signing keypair used
   on-chain. Generated via `sphincs.NewKeyManager().GenerateKey()`.
2. **A recovery mnemonic** — a 12-word SIPS-0003 phrase plus a Base32
   passkey, generated via `seed.GenerateKeys()`. This is your wallet's root
   of trust. **It is printed to the terminal exactly once and never written
   to disk by this code.** Write it down somewhere safe; there is no way to
   recover it from the keystore files if you lose it.
3. **An encryption passphrase** — a separate, shorter password you type in
   (prompted, masked, entered twice to confirm) that protects the SK at
   rest. This is *not* the mnemonic. Reusing the mnemonic as this password
   would mean anyone who watches you unlock the wallet has effectively seen
   your recovery phrase too.

The SK is encrypted with this passphrase (AES-256-GCM, key derived via
Argon2id + SHA3-512 stretching) before it ever touches disk. The PK is
stored unencrypted, since public keys aren't secret.

## Where keys are actually stored

### Disk keystore (default)

```
~/.sphinx/disk-keystore/keys/<key-id>.json
```

That's under your **home directory**, not the project folder — and `.sphinx`
is a hidden (dotfile) directory, so a plain `ls` or Finder window won't show
it by default.

To look at what's there:

```bash
ls -la ~/.sphinx/disk-keystore/keys/
```

Each `.json` file is one key pair, named like
`disk_key_<unix-nano-timestamp>_<random-hex>.json`, permissions `0600`
(owner read/write only). Example fields inside one of these files:

```json
{
  "id": "disk_key_1782046724252676000_cbaddd3584c989a9",
  "encrypted_sk": "90cf3067...",
  "public_key": "...",
  "address": "...",
  "key_type": "sphincs+",
  "wallet_type": "DiskWallet",
  "chain_id": 7331,
  "created_at": "..."
}
```

`encrypted_sk` is ciphertext — opening the file does not expose the private
key. You need the passphrase to decrypt it (see below).

If `~/.sphinx/disk-keystore/` doesn't exist yet, it gets created
automatically the first time `test_encrypt.go` runs successfully.

### USB keystore (manual backup, not automatic)

`test_encrypt.go` never touches USB storage on its own. To copy keys onto a
USB drive, you run the separate demo:

```bash
cd src/accounts/usbdemo
go run .
```

This writes to a `sphinx-usb-keystore/` folder on whatever path you set as
`usbPath` in that file (edit it to your actual mounted drive first, e.g.
`/Volumes/MYUSB` on macOS):

```
<your-usb-drive>/sphinx-usb-keystore/
├── usb-info.json
├── keys/
│   └── <key-id>.json          <- current, restorable copy
└── backup/
    └── <timestamp>/
        ├── backup-manifest.json
        └── <key-id>.json      <- dated audit copy, not used for restore
```

`keys/` is what actually gets read back on restore. `backup/<timestamp>/`
is a historical record — useful for "what did the wallet look like on this
date," but not what `RestoreToDisk` reads from.

**Important:** this is encrypted-blob backup to removable storage, not a
hardware wallet. The same AES-GCM ciphertext that's on your disk keystore
gets copied to the USB drive's filesystem — there's no secure element, no
on-device signing. A Ledger or similar never lets the raw key leave the
device at all; this just gives you an offline copy of the same encrypted
file.

## Commands to inspect everything

```bash
# List all keys in the default disk keystore
ls -la ~/.sphinx/disk-keystore/keys/

# Pretty-print one key file's metadata (won't show you the actual secret —
# encrypted_sk is ciphertext)
cat ~/.sphinx/disk-keystore/keys/<key-id>.json | python3 -m json.tool

# Count how many keys you've generated so far
ls ~/.sphinx/disk-keystore/keys/ | wc -l

# Find the keystore even if it's not at the expected path
find ~ -iname "disk_key_*" 2>/dev/null
find / -iname "disk-keystore" -type d 2>/dev/null

# Check a mounted USB drive for a Sphinx keystore
ls -la /Volumes/<your-drive-name>/sphinx-usb-keystore/keys/   # macOS
ls -la /media/<user>/<your-drive-name>/sphinx-usb-keystore/keys/  # Linux
```

## Running the demos

```bash
# Generate a new key pair, encrypt it, store it to disk, then reload +
# decrypt + verify it in the same run. Prompts for a passphrase twice on
# creation, once again on the simulated reload.
cd src/core/wallet
go run .

# Back up everything currently in the disk keystore to a mounted USB
# drive, then restore it back (round-trip test). Edit usbPath inside the
# file first.
cd src/accounts/usbdemo
go run .
```

Both commands need `go get golang.org/x/term` run once beforehand (used
for masked passphrase input).

## What each generated wallet actually is

Every time you run `test_encrypt.go`, it generates a **brand new,
unrelated** key pair and mnemonic — there's no continuity between runs.
If you've run it multiple times, you'll have multiple independent
`disk_key_*.json` files, each a separate wallet. None of these should be
treated as "real" funded wallets; they're created by a test/demo script,
and the mnemonics printed during testing were very likely not written down
anywhere durable.

## Known gaps / things not yet done

- **No real address derivation.** `test_encrypt.go` uses
  `pkBytes[:20]` (a raw prefix slice) as a placeholder address. This is
  explicitly marked in the code as not a real address scheme.
- **No HD derivation path.** `derivationPath` is left as an empty string.
- **No Ledger / hardware wallet support.** "USB keystore" in this codebase
  means encrypted files on removable storage, not a hardware secure
  element. See the clarification above.
- **Two duplicate `getDefaultDiskStoragePath()` implementations** exist
  (in `disk/local.go` and `utils/utils.go`), currently returning identical
  paths but maintained as separate copies — worth consolidating into one
  shared source of truth.
- **`wordslist.go`'s mnemonic word list is fetched live from GitHub** at
  generation time rather than embedded in the binary, which means
  mnemonic generation currently requires network access and depends on a
  remote repository staying available and unchanged. This is a known open
  item, not yet resolved.s
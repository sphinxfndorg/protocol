# SPX Wallet

Build and run with:

```sh
go run ./src/gui/cmd
```

The wallet starts an embedded node. Data is stored under
`~/.sphinx/wallet-node`; wallet keys use the existing SPIF key store. The
wallet RPC listens on `127.0.0.1:8700`, P2P on `127.0.0.1:30303`, and HTTP
on `127.0.0.1:8545`.

Known limitations: the embedded node currently joins as a normal validator and
is intended for devnet use; configured seeds are trusted for synchronization;
the effective network may be forced to devnet by the existing bind startup
override. The UI displays the effective network returned by RPC.

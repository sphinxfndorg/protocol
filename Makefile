# Sphinx protocol — development tasks.
#
# Measured on this machine (darwin/arm64), non-race `go test`:
#
#   src/policy/...  2s      src/core/...   20s
#   src/cli/...     3s      src/consensus/... 52s
#   src/core/musig  26s     src/bind/...   86s
#
# So a plain `go test ./src/...` finishes well inside go's 10m per-package
# default and needs no special handling. What DOES need a long timeout is
# the race detector (consensus alone is ~10m, -count=3 is ~24m) and the
# localnet integration suite (~35m: it boots real SPHINCS+ validators).
# Those are the only reasons the timeouts below exist.

GO           ?= go
TIMEOUT      ?= 20m
RACE_TIMEOUT ?= 40m
LOCALNET_TIMEOUT ?= 90m

.PHONY: all build fmt fmt-check vet test test-race test-localnet check clean

all: check

## build: compile the CLI binary (./sphinx)
build:
	$(GO) build -o sphinx ./src/cli

## fmt: rewrite all Go sources with gofmt
fmt:
	gofmt -w src

## fmt-check: fail if anything is unformatted.
##
## NOT part of `check`, and deliberately so: 12 files are unformatted on a
## clean checkout, all of it trailing-comment alignment inside struct literals
## (src/contracts, src/policy/params.go, src/http/explorer.go, src/usi/...,
## src/network/port.go). That drift predates this Makefile and is cosmetic, so
## gating CI on it would make `check` red for reasons unrelated to any change.
## Run `make fmt` once to clear it, then this becomes a useful regression gate.
fmt-check:
	@out=$$(gofmt -l src); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

## vet: go vet, including the build-tagged localnet integration tests
vet:
	$(GO) vet ./src/...
	$(GO) vet -tags localnet ./src/cli/utils/

## test: full suite. No per-package split — it only hid the slow packages.
test:
	$(GO) test -timeout $(TIMEOUT) ./src/...

## test-race: race detector on the concurrency-sensitive packages.
test-race:
	$(GO) test -race -timeout $(RACE_TIMEOUT) ./src/consensus/... ./src/bind/... ./src/core/...

## test-localnet: real multi-process localnets. Slow (~35m) and gated by a tag,
## so it is deliberately not part of `test`.
test-localnet:
	$(GO) test -tags localnet -timeout $(LOCALNET_TIMEOUT) -v ./src/cli/utils/

## check: what CI should run. fmt-check is intentionally excluded — see above.
check: vet test

clean:
	rm -f sphinx

# Sphinx protocol — development tasks.
#
# Why this exists: `go test`'s default timeout is 10m PER PACKAGE, and
# src/core's SPHINCS+-heavy suites take ~12m on a laptop. Running
# `go test ./src/core/` bare therefore dies with
#     panic: test timed out after 10m0s
# on a suite that has zero failures — a confusing hour for whoever hits it.
# Use these targets, or pass -timeout explicitly.

.PHONY: test test-core test-musig test-cli test-policy

# 40m: src/core measured at ~12m serial on this machine, with headroom for a
# slower or contended runner.
GO_TEST_TIMEOUT ?= 40m

test: test-policy test-musig test-cli test-core

test-policy:
	go test -timeout $(GO_TEST_TIMEOUT) ./src/policy/...

test-musig:
	go test -timeout $(GO_TEST_TIMEOUT) ./src/core/musig/...

test-cli:
	go test -timeout $(GO_TEST_TIMEOUT) ./src/cli/...

test-core:
	go test -timeout $(GO_TEST_TIMEOUT) ./src/core/...

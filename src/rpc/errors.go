// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/erros.go
package rpc

import "errors"

// Custom errors for RPC operations.
var (
	ErrBufferTooSmall       = errors.New("size of the buffer is too small")
	ErrInvalidNodeID        = errors.New("invalid node ID")
	ErrInvalidAddress       = errors.New("invalid remote address")
	ErrUnsupportedRPCType   = errors.New("unsupported RPC type")
	ErrInvalidMessageFormat = errors.New("invalid message format")

	// RPC hardening: authentication error
	ErrCodeUnauthorized = -32501
)

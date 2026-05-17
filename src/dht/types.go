// Copyright 2024 Lei Ni (nilei81@gmail.com)
//
// This library follows a dual licensing model -
//
// - it is licensed under the 2-clause BSD license if you have written evidence showing that you are a licensee of github.com/lni/pothos
// - otherwise, it is licensed under the GPL-2 license
//
// See the LICENSE file for details
// https://github.com/lni/dht/tree/main
//
// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/dht/types.go
package dht

import (
	"net"
	"time"

	"github.com/elliotchance/orderedmap/v2"
	"github.com/lni/goutils/syncutil"
	"github.com/sphinxorg/protocol/src/network"
	"github.com/sphinxorg/protocol/src/rpc"
	"go.uber.org/zap"
)

// DHTConfig is the config for the DHT.
type DHTConfig struct {
	Proto   string
	Address net.UDPAddr
	Routers []net.UDPAddr
	Secret  uint16
}

type Config = DHTConfig

type schedulable func()

type timeout struct {
	RPCID     rpc.RPCID
	RPCType   rpc.RPCType
	NodeID    rpc.NodeID
	Target    rpc.NodeID
	Iteration int
}

type sendReq struct {
	Msg         rpc.Message
	Addr        net.UDPAddr
	EncodedData []byte // Add field for encoded security.Message
}

type reqType int8

const (
	RequestJoin reqType = iota
	RequestPut
	RequestGet
	RequestGetFromCached
)

type request struct {
	RequestType  reqType
	Target       network.Key
	Value        []byte
	TTL          uint16
	FromCachedCh chan [][]byte
}

type DHT struct {
	cfg         Config
	self        rpc.Remote
	address     net.UDPAddr
	conn        *conn
	rt          *routingTable
	ongoing     *rpc.QueryManager
	store       *rpc.KVStore
	cached      *rpc.KVStore
	scheduledCh chan schedulable
	sendMsgCh   chan sendReq
	requestCh   chan request
	timeoutCh   chan timeout
	loopbackCh  chan rpc.Message
	lastJoin    time.Time
	lastRefill  time.Time
	stopper     *syncutil.Stopper
	log         *zap.Logger
}

type conn struct {
	ReceivedCh chan rpc.Message
	sendBuf    []byte
	recvBuf    []byte
	c          *net.UDPConn
	log        *zap.Logger // Added logger
}

type remoteRecord struct {
	remote   rpc.Remote
	lastSeen time.Time
}

type kBucket struct {
	k       int
	buckets *orderedmap.OrderedMap[rpc.NodeID, remoteRecord]
}

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

// go/src/dht/dht.go
package dht

import (
	"encoding/json"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/lni/goutils/syncutil"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/network"

	"github.com/sphinxfndorg/protocol/src/rpc"
	"go.uber.org/zap"
)

// Constants for DHT configuration and timing
const (
	// cachedTTL is the time-to-live for cached entries (60 seconds)
	cachedTTL uint16 = 60
	// ongoingManagerGCInterval is how often to garbage collect the query manager
	ongoingManagerGCInterval = 5 * time.Second
	// storeGCInterval is how often to garbage collect the key-value store
	storeGCInterval = 60 * time.Second
	// staledRemotePingInterval is how often to ping stale remote nodes
	staledRemotePingInterval = 120 * time.Second
	// emptyKBucketRefillInterval is how often to refill empty k-buckets
	emptyKBucketRefillInterval = 600 * time.Second
	// routingTableGCInterval is how often to garbage collect the routing table
	routingTableGCInterval = 300 * time.Second
	// defaultFindNodeTimeout is the default timeout for find node operations
	defaultFindNodeTimeout = 100 * time.Millisecond
	// minDelay is the minimum delay for scheduled operations
	minDelay = 50 * time.Millisecond
	// minJoinInterval is the minimum interval between join requests
	minJoinInterval = 20 * time.Millisecond
	// minRefillInterval is the minimum interval between refill operations
	minRefillInterval = 90 * time.Millisecond
	// maxFindNodeIteration is the maximum number of find node iterations
	maxFindNodeIteration = 24
)

// magicNumber is the protocol magic number for message identification
var (
	magicNumber = [2]byte{0xEF, 0x2B}
)

// NewDHT creates a new Distributed Hash Table instance
// This initializes the Kademlia-based DHT for peer discovery and data storage
func NewDHT(cfg Config, logger *zap.Logger) (*DHT, error) {
	// Generate a random node ID for this DHT node
	nodeID := network.GetRandomNodeID()

	// Create a new UDP connection for DHT communication
	conn, err := newConn(cfg, logger)
	if err != nil {
		return nil, err
	}

	// Initialize and return the DHT struct with all components
	return &DHT{
		cfg:         cfg,                                                                     // DHT configuration
		self:        rpc.Remote{NodeID: rpc.NodeID(nodeID), Address: cfg.Address},            // Self node info
		address:     cfg.Address,                                                             // Local address
		conn:        conn,                                                                    // UDP connection
		rt:          newRoutingTable(DefaultK, DefaultBits, rpc.NodeID(nodeID), cfg.Address), // Routing table
		ongoing:     rpc.NewQueryManager(),                                                   // Manages ongoing queries
		store:       rpc.NewKVStore(),                                                        // Persistent key-value store
		cached:      rpc.NewKVStore(),                                                        // Cache for temporary storage
		scheduledCh: make(chan schedulable, 16),                                              // Channel for scheduled functions
		sendMsgCh:   make(chan sendReq, 16),                                                  // Channel for sending messages
		requestCh:   make(chan request, 16),                                                  // Channel for handling requests
		timeoutCh:   make(chan timeout, 16),                                                  // Channel for timeout events
		loopbackCh:  make(chan rpc.Message, 16),                                              // Channel for loopback messages
		stopper:     syncutil.NewStopper(),                                                   // Stopper for graceful shutdown
		log:         logger,                                                                  // Logger instance
	}, nil
}

// Start begins the DHT operation by launching all worker goroutines
func (d *DHT) Start() error {
	// ── FIX: DHT may have a nil conn if the port was already in use ──
	// When newConn returns nil, nil (e.g. port collision), DHT is still
	// created but cannot send/receive on UDP. Start the stub workers
	// anyway so the DHT lifecycle is consistent, but skip the receiver
	// loop (which would panic on a nil conn).
	if d.conn != nil {
		// Start message receiver loop
		d.stopper.RunWorker(func() {
			if err := d.conn.ReceiveMessageLoop(d.stopper.ShouldStop()); err != nil {
				d.log.Error("ReceiveMessageLoop failed", zap.Error(err))
				return
			}
		})
	}

	// Start message sender worker
	d.stopper.RunWorker(func() {
		d.sendMessageWorker()
	})

	// Start main event loop
	d.stopper.RunWorker(func() {
		d.loop()
	})

	// Only send join request if we have a connection (port not in use)
	if d.conn != nil {
		// Send initial join request to bootstrap into the network
		d.requestToJoin()

		// Schedule periodic join requests (every second)
		d.schedule(time.Second, func() {
			d.requestToJoin()
		})
	}

	return nil
}

// Close gracefully shuts down the DHT
func (d *DHT) Close() error {
	d.log.Debug("Stopping DHT")
	d.stopper.Stop() // Stop all worker goroutines
	d.log.Debug("Stopper stopped")
	// ── FIX: d.conn may be nil if port was already in use ──
	if d.conn != nil {
		return d.conn.Close() // Close the UDP connection
	}
	return nil
}

// Put implements network.DHT.Put.
// Stores a key-value pair in the DHT with a specified TTL
func (d *DHT) Put(key network.Key, value []byte, ttl uint16) {
	// Create a put request
	req := request{
		RequestType: RequestPut,
		Target:      key,
		Value:       value,
		TTL:         ttl,
	}
	// Submit the request for processing
	d.request(req)
}

// Get implements network.DHT.Get.
// Retrieves values associated with a key from the DHT.
//
// Note: responses to RPCGet queries are written into d.cached by
// handleGetResponse (running on the DHT's main loop goroutine), not pushed
// back through a call-local channel. So this method fires the query, waits
// out the timeout window to give remote nodes a chance to reply and populate
// the cache, and then reads from the cache — it does not block on a channel
// no one writes to.
func (d *DHT) Get(key network.Key) ([][]byte, bool) {
	// Generate a unique RPC ID for this query
	rpcID := rpc.GetRPCID()

	// Register this get operation with the query manager
	d.ongoing.AddGet(rpcID)

	// Create the get query message
	msg := rpc.Message{
		RPCType: rpc.RPCGet,
		RPCID:   rpcID,
		Query:   true,
		Target:  rpc.NodeID(key),
		From:    d.self,
	}

	// Find the k-nearest nodes to the target
	kn := d.rt.KNearest(rpc.NodeID(key))

	// Send the query to all k-nearest nodes
	for _, rt := range kn {
		d.sendMessage(msg, rt.Address)
	}

	// Wait for the response window to elapse (or for shutdown), then read
	// whatever handleGetResponse has placed in the cache.
	select {
	case <-time.After(defaultFindNodeTimeout):
		values, ok := d.cached.Get(rpc.Key(key))
		return values, ok
	case <-d.stopper.ShouldStop():
		// DHT is stopping
		return nil, false
	}
}

// ScheduleGet implements network.DHT.ScheduleGet.
// Schedules a get operation after a specified delay
func (d *DHT) ScheduleGet(delay time.Duration, key network.Key) {
	// Run a worker that will execute after the delay
	d.stopper.RunWorker(func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-d.stopper.ShouldStop():
			// DHT is stopping, abort
		case <-timer.C:
			// Delay expired, execute the get
			d.Get(key)
		}
	})
}

// GetCached implements network.DHT.GetCached.
// Retrieves values from the local cache only (no network query)
func (d *DHT) GetCached(key network.Key) [][]byte {
	v, _ := d.cached.Get(rpc.Key(key))
	return v
}

// KNearest implements network.DHT.KNearest.
// Returns the k-nearest nodes to a target node ID from the routing table
func (d *DHT) KNearest(target network.NodeID) []network.Remote {
	// Get k-nearest from internal routing table
	rpcRemotes := d.rt.KNearest(rpc.NodeID(target))

	// Convert from RPC.Remote to network.Remote
	remotes := make([]network.Remote, len(rpcRemotes))
	for i, r := range rpcRemotes {
		remotes[i] = network.Remote{
			NodeID:  network.NodeID(r.NodeID),
			Address: r.Address,
		}
	}
	return remotes
}

// SelfNodeID implements network.DHT.SelfNodeID.
// Returns this node's own ID
func (d *DHT) SelfNodeID() network.NodeID {
	return network.NodeID(d.self.NodeID)
}

// PingNode implements network.DHT.PingNode.
// Sends a ping message to a remote node to check liveness
func (d *DHT) PingNode(nodeID network.NodeID, addr net.UDPAddr) {
	// Create ping message
	msg := rpc.Message{
		RPCType: rpc.RPCPing,
		Query:   true,
		RPCID:   rpc.GetRPCID(),
		From:    d.self,
		Target:  rpc.NodeID(nodeID),
	}

	// Register ping with query manager
	d.ongoing.AddPing(msg.RPCID, rpc.NodeID(nodeID))

	// Send the ping
	d.sendMessage(msg, addr)
}

// Join implements network.DHT.Join.
// Sends a join request to bootstrap routers to join the network
func (d *DHT) Join() {
	// Rate limit join requests
	if !d.allowToJoin() {
		return
	}

	// Generate unique RPC ID
	rpcID := rpc.GetRPCID()

	// Register join with query manager
	d.ongoing.AddJoin(rpcID)

	// Create join message
	msg := rpc.Message{
		RPCType: rpc.RPCJoin,
		Query:   true,
		RPCID:   rpcID,
		Target:  d.self.NodeID,
		From:    d.self,
	}

	// Send join request to all configured router nodes
	for _, router := range d.cfg.Routers {
		d.sendMessage(msg, router)
	}
}

// sendMessageWorker processes outgoing messages from the sendMsgCh channel
func (d *DHT) sendMessageWorker() {
	// ── FIX: If conn is nil (port collision), silently drain sendMsgCh ──
	// Without this, any code path that tries to send a DHT message will
	// panic on nil pointer dereference of d.conn.
	for {
		select {
		case <-d.stopper.ShouldStop():
			return
		case req := <-d.sendMsgCh:
			if d.conn == nil {
				// DHT disabled (port in use) — just drop the message
				continue
			}
			if err := d.conn.SendMessage(req.EncodedData, req.Addr); err != nil {
				d.log.Debug("Failed to send message", zap.Error(err))
			}
		}
	}
}

// loop is the main event loop for the DHT
// Handles timers, channels, and scheduled operations
func (d *DHT) loop() {
	// Add random jitter to timers to prevent thundering herd
	ri := time.Duration(rand.Uint64()%5000) * time.Millisecond

	// ── FIX: If conn is nil (port collision), create a closed channel so the
	// select below never blocks on d.conn.ReceivedCh — otherwise the main
	// loop would spin forever waiting for a nil channel that will never close.
	var receivedCh chan rpc.Message
	if d.conn != nil {
		receivedCh = d.conn.ReceivedCh
	} else {
		// Use a closed channel that immediately returns zero values
		// (which are ignored by handleMessage since they have no sender).
		receivedCh = make(chan rpc.Message)
		close(receivedCh)
	}

	// Initialize timers with jitter
	storeGCTicker := time.NewTicker(storeGCInterval + ri)
	defer storeGCTicker.Stop()

	stalePingTicker := time.NewTicker(staledRemotePingInterval + ri)
	defer stalePingTicker.Stop()

	emptyKBucketRefillTicker := time.NewTicker(emptyKBucketRefillInterval + ri)
	defer emptyKBucketRefillTicker.Stop()

	routingTableGCTicker := time.NewTicker(routingTableGCInterval + ri)
	defer routingTableGCTicker.Stop()

	ongoingGCTicker := time.NewTicker(ongoingManagerGCInterval + ri)
	defer ongoingGCTicker.Stop()

	// Main event loop
	for {
		select {
		case <-d.stopper.ShouldStop():
			// DHT is stopping
			d.log.Debug("Main loop exiting")
			return

		case msg := <-d.loopbackCh:
			// Handle loopback message (self-addressed)
			d.handleMessage(msg)

		case <-storeGCTicker.C:
			// Periodic store garbage collection
			d.storeGC()

		case <-ongoingGCTicker.C:
			// Periodic query manager garbage collection
			d.log.Debug("Query manager GC called")
			d.ongoing.GC()

		case fn := <-d.scheduledCh:
			// Execute scheduled function on main thread
			fn()

		case <-routingTableGCTicker.C:
			// Periodic routing table garbage collection
			d.routingTableGC()

		case <-emptyKBucketRefillTicker.C:
			// Periodic refill of empty k-buckets
			d.refillEmptyKBucket(false)

		case <-stalePingTicker.C:
			// Periodic ping of stale remote nodes
			d.pingStaleRemotes()

		case msg := <-receivedCh:
			// Handle incoming message from network
			d.handleMessage(msg)

		case req := <-d.requestCh:
			// Handle internal request
			d.handleRequest(req)

		case timeout := <-d.timeoutCh:
			// Handle timeout event
			d.handleTimeout(timeout)
		}
	}
}

// request submits a request to the request channel
func (d *DHT) request(r request) {
	select {
	case <-d.stopper.ShouldStop():
		// DHT is stopping, drop request
	case d.requestCh <- r:
		// Request submitted successfully
	}
}

// handleRequest processes different types of internal requests
func (d *DHT) handleRequest(req request) {
	switch req.RequestType {
	case RequestJoin:
		// Join request
		d.Join()
	case RequestPut:
		// Put (store) request
		d.put(req.Target, req.Value, req.TTL)
	case RequestGet:
		// Get (retrieve) request
		d.get(req.Target)
	case RequestGetFromCached:
		// Get from cache only
		d.getFromCached(req.Target, req.FromCachedCh)
	default:
		// Unknown request type
		d.log.Error("Unknown request type", zap.Int("type", int(req.RequestType)))
	}
}

// requestToJoin submits a join request
func (d *DHT) requestToJoin() {
	d.request(request{RequestType: RequestJoin})
}

// put handles a put operation by first finding nodes, then storing the value
func (d *DHT) put(key network.Key, value []byte, ttl uint16) {
	// Define completion callback for find node operation
	onCompletion := func() {
		d.log.Debug("Find node completed for put query", d.targetField(key), d.localNodeIDField())
		// After finding nodes, actually store the key-value pair
		d.putKeyValue(key, value, ttl)
	}
	// Find nodes closest to the key, then execute callback
	d.doFindNode(rpc.NodeID(key), onCompletion)
}

// get handles a get operation by first finding nodes, then retrieving values
func (d *DHT) get(key network.Key) {
	// Define completion callback for find node operation
	onCompletion := func() {
		d.log.Debug("Find node completed for get query", d.targetField(key), d.localNodeIDField())
		// After finding nodes, actually retrieve the key-value pair
		d.getKeyValue(key)
	}
	// Find nodes closest to the key, then execute callback
	d.doFindNode(rpc.NodeID(key), onCompletion)
}

// getFromCached retrieves a value from the local cache and sends it back on the channel
func (d *DHT) getFromCached(target network.Key, ch chan [][]byte) {
	// Get from cache
	v, _ := d.cached.Get(rpc.Key(target))

	// Send result back on channel
	select {
	case <-d.stopper.ShouldStop():
		// DHT stopping, drop result
	case ch <- v:
		// Result sent
	}
}

// putKeyValue sends store requests to the k-nearest nodes
func (d *DHT) putKeyValue(target network.Key, value []byte, ttl uint16) {
	// Create store message
	msg := rpc.Message{
		RPCType: rpc.RPCStore,
		Query:   true,
		RPCID:   rpc.GetRPCID(),
		Target:  rpc.NodeID(target),
		From:    d.self,
		TTL:     ttl,
		Values:  [][]byte{value},
	}

	// Find k-nearest nodes to the target
	kn := d.rt.KNearest(rpc.NodeID(target))

	// Send store request to each of the k-nearest nodes
	for _, rt := range kn {
		d.sendMessage(msg, rt.Address)
	}
}

// getKeyValue sends get requests to the k-nearest nodes
func (d *DHT) getKeyValue(target network.Key) {
	// Generate unique RPC ID
	rpcID := rpc.GetRPCID()

	// Register this get operation
	d.ongoing.AddGet(rpcID)

	// Create get message
	msg := rpc.Message{
		RPCType: rpc.RPCGet,
		RPCID:   rpcID,
		Query:   true,
		Target:  rpc.NodeID(target),
		From:    d.self,
	}

	// Find k-nearest nodes to the target
	kn := d.rt.KNearest(rpc.NodeID(target))

	// Send get request to each of the k-nearest nodes
	for _, rt := range kn {
		d.sendMessage(msg, rt.Address)
	}
}

// doFindNode performs a recursive node lookup in the DHT
func (d *DHT) doFindNode(target rpc.NodeID, onCompletion schedulable) {
	// Get k-nearest nodes from routing table
	kn := d.rt.KNearest(target)

	if len(kn) > 0 {
		// Generate unique RPC ID
		rpcID := rpc.GetRPCID()

		// Add find node query to ongoing manager
		q := d.ongoing.AddFindNode(rpcID, target, onCompletion)

		// Send find node request to each of the k-nearest nodes
		for _, rt := range kn {
			d.sendFindNodeRequest(target, rpcID, rt, 0)
			q.Request(rt.NodeID) // Track that we've sent a request to this node
		}
	}

	// If we don't have enough nodes, schedule a join to get more
	if len(kn) < DefaultK {
		d.schedule(getRandomDelay(time.Second), func() {
			d.Join()
		})
	}
}

// handleMessage processes incoming RPC messages
func (d *DHT) handleMessage(msg rpc.Message) {
	// Verify message secret matches configuration
	if msg.Secret != d.cfg.Secret {
		return
	}

	// Update routing table with the sender's information
	d.rt.Observe(msg.From.NodeID, msg.From.Address)

	// Handle based on message type (query or response)
	if msg.Query {
		d.handleQuery(msg) // This is a query (request)
		return
	}
	d.handleResponse(msg) // This is a response
}

// toLocalNode checks if an address corresponds to the local node
func (d *DHT) toLocalNode(addr net.UDPAddr) bool {
	return d.self.Address.IP.Equal(addr.IP) &&
		d.self.Address.Port == addr.Port &&
		d.self.Address.Zone == addr.Zone
}

// sendMessage encodes and sends an RPC message to a remote node
func (d *DHT) sendMessage(m rpc.Message, addr net.UDPAddr) {
	// ── FIX: Silently drop messages if DHT is disabled (port collision) ──
	if d.conn == nil {
		return
	}

	// Set the secret before marshaling/encoding so it is actually included on the wire
	m.Secret = d.cfg.Secret

	// Verify message has required fields
	d.verifyMessage(m)

	// Use getMessageBuf to add magic header and BLAKE3 hash.
	// EncodeMessage marshals m internally, so there is no need to marshal here
	// and then unmarshal into a throwaway wrapper just to pass it back in.
	encodedMsg, err := d.conn.EncodeMessage(m)
	if err != nil {
		d.log.Error("Failed to encode message with getMessageBuf", zap.Error(err))
		return
	}

	// encodedMsg is a raw binary buffer (magic number + length + payload +
	// BLAKE3 hash), not JSON text. Data is json.RawMessage, so it must hold
	// valid JSON — assigning the binary bytes directly made the outer
	// json.Marshal below fail with "invalid character ... looking for
	// beginning of value" as soon as a byte like 0xEF appeared.
	// json.Marshal of a []byte auto-encodes it as a base64 JSON string
	// (matching how bind.go's "rpc" case round-trips raw bytes through
	// Message.Data), so marshal encodedMsg instead of assigning it directly.
	b64Msg, err := json.Marshal(encodedMsg)
	if err != nil {
		d.log.Error("Failed to base64/JSON-encode message payload", zap.Error(err))
		return
	}

	// Wrap in security message for encryption/integrity
	secMsg := &security.Message{Type: "rpc", Data: b64Msg}
	encodedData, err := secMsg.Encode()
	if err != nil {
		d.log.Error("Failed to encode security message", zap.Error(err))
		return
	}

	// Create send request
	req := sendReq{Addr: addr, Msg: m, EncodedData: encodedData}

	// Check if this is a loopback message (to self)
	if d.toLocalNode(addr) {
		select {
		case d.loopbackCh <- m:
			// Loopback message sent
		default:
			d.log.Warn("loopbackCh full, dropping message")
		}
	} else {
		// Send to remote node
		select {
		case d.sendMsgCh <- req:
			// Message queued for sending
		default:
			d.log.Warn("sendMsgCh full, dropping message")
		}
	}
}

// handleQuery processes incoming query messages (requests)
func (d *DHT) handleQuery(msg rpc.Message) {
	switch msg.RPCType {
	case rpc.RPCPing:
		// Handle ping query
		d.handlePingQuery(msg)
	case rpc.RPCJoin:
		// Handle join query
		d.handleJoinQuery(msg)
	case rpc.RPCFindNode:
		// Handle find node query
		d.handleFindNodeQuery(msg)
	case rpc.RPCStore:
		// Handle store (put) query
		d.handlePutQuery(msg)
	case rpc.RPCGet:
		// Handle get query
		d.handleGetQuery(msg)
	default:
		// Unknown RPC type
		d.log.Error("Unknown RPC type", zap.String("type", strconv.Itoa(int(msg.RPCType))))
	}
}

// handlePutQuery processes a store (put) query from a remote node
func (d *DHT) handlePutQuery(msg rpc.Message) {
	d.log.Debug("Received put query", d.fromField(msg.From), d.localNodeIDField(), d.targetField(network.Key(msg.Target)))

	// Store the value if provided
	if len(msg.Values) > 0 {
		d.store.Put(rpc.Key(msg.Target), msg.Values[0], msg.TTL)
	}
}

// handleGetQuery processes a get query from a remote node
func (d *DHT) handleGetQuery(msg rpc.Message) {
	d.log.Debug("Received get query", d.fromField(msg.From), d.localNodeIDField(), d.targetField(network.Key(msg.Target)))

	// Retrieve values from store
	values, ok := d.store.Get(rpc.Key(msg.Target))
	if !ok {
		return // No values found
	}

	// Split into 4KB batches for transmission
	batches := rpc.To4KBatches(values)

	// Send each batch as a separate response
	for _, v := range batches {
		reply := rpc.Message{
			RPCType: rpc.RPCGet,
			Query:   false, // This is a response
			Target:  msg.Target,
			RPCID:   msg.RPCID,
			From:    d.self,
			Values:  v,
		}
		d.sendMessage(reply, msg.From.Address)
	}
}

// handleJoinQuery processes a join query from a remote node
func (d *DHT) handleJoinQuery(msg rpc.Message) {
	d.log.Debug("Received join query", d.fromField(msg.From), d.localNodeIDField())

	// Prepare response with k-nearest nodes to the requester
	resp := rpc.Message{
		RPCType: msg.RPCType,
		Query:   false, // This is a response
		RPCID:   msg.RPCID,
		From:    d.self,
		Target:  msg.Target,
		Nodes:   d.rt.KNearest(msg.Target), // Include nearby nodes
	}

	// Send response
	d.sendMessage(resp, msg.From.Address)
}

// handlePingQuery processes a ping query from a remote node
func (d *DHT) handlePingQuery(msg rpc.Message) {
	// Prepare pong response
	resp := rpc.Message{
		RPCType: msg.RPCType,
		Query:   false, // This is a response
		RPCID:   msg.RPCID,
		From:    d.self,
	}

	// Send response
	d.sendMessage(resp, msg.From.Address)
}

// handleFindNodeQuery processes a find node query from a remote node
func (d *DHT) handleFindNodeQuery(msg rpc.Message) {
	d.log.Debug("Received find node query", d.fromField(msg.From), d.localNodeIDField(), d.targetField(network.Key(msg.Target)))

	// Validate target is not empty
	if network.Key(msg.Target).IsEmpty() {
		d.log.Error("Empty target in find node query")
		return
	}

	// Get k-nearest nodes to the target
	kn := d.rt.KNearest(msg.Target)

	// Prepare response
	resp := rpc.Message{
		RPCType: msg.RPCType,
		Query:   false, // This is a response
		RPCID:   msg.RPCID,
		From:    d.self,
		Nodes:   kn,
		Target:  msg.Target,
	}

	// Send response
	d.sendMessage(resp, msg.From.Address)
}

// handleResponse processes incoming response messages
func (d *DHT) handleResponse(msg rpc.Message) {
	// Check if this response is expected
	if !d.ongoing.IsExpectedResponse(msg) {
		return
	}

	// Handle based on response type
	switch msg.RPCType {
	case rpc.RPCPing:
		// Ping response - nothing to do
	case rpc.RPCGet:
		// Get response
		d.handleGetResponse(msg)
	case rpc.RPCFindNode:
		// Find node response
		d.handleFindNodeResponse(msg)
	case rpc.RPCJoin:
		// Join response
		d.handleJoinResponse(msg)
	default:
		// Unknown response type
		d.log.Error("Unknown response type", zap.String("type", strconv.Itoa(int(msg.RPCType))))
	}
}

// handleGetResponse processes a get response containing values
func (d *DHT) handleGetResponse(msg rpc.Message) {
	// Cache the received values
	for _, v := range msg.Values {
		d.cached.Put(rpc.Key(msg.Target), v, cachedTTL)
	}
}

// handleFindNodeResponse processes a find node response containing node information
func (d *DHT) handleFindNodeResponse(msg rpc.Message) {
	// Get the query associated with this RPC ID
	q, ok := d.ongoing.GetQuery(msg.RPCID)
	if !ok {
		return
	}

	// Notify query that this node has responded
	if q.OnResponded(msg.From.NodeID) {
		// Add returned nodes to routing table
		for _, node := range msg.Nodes {
			d.rt.Observe(node.NodeID, node.Address)
		}

		// Continue recursive lookup with next iteration
		iter := int(msg.Iteration) + 1
		d.recursiveFindNode(msg.Target, msg.RPCID, q, iter)
	}
}

// handleJoinResponse processes a join response containing node information
func (d *DHT) handleJoinResponse(msg rpc.Message) {
	// Add returned nodes to routing table
	for _, node := range msg.Nodes {
		d.rt.Observe(node.NodeID, node.Address)
	}

	// Schedule refill of empty k-buckets
	d.schedule(100*time.Millisecond, func() {
		d.refillEmptyKBucket(true)
	})
}

// sendFindNodeRequest sends a find node request to a specific remote node
func (d *DHT) sendFindNodeRequest(target rpc.NodeID, rpcID rpc.RPCID, rt rpc.Remote, iter int) {
	// Only send if within iteration limit
	if iter <= maxFindNodeIteration {
		// Create find node message
		msg := rpc.Message{
			RPCType:   rpc.RPCFindNode,
			Query:     true,
			RPCID:     rpcID,
			From:      d.self,
			Target:    target,
			Iteration: uint8(iter),
		}
		// Send the request
		d.sendMessage(msg, rt.Address)
	}

	// Schedule timeout for this request
	d.runWorker(defaultFindNodeTimeout, func() {
		timeout := timeout{
			RPCID:     rpcID,
			RPCType:   rpc.RPCFindNode,
			NodeID:    rt.NodeID,
			Target:    target,
			Iteration: iter,
		}
		// Send timeout to timeout channel
		select {
		case d.timeoutCh <- timeout:
		case <-d.stopper.ShouldStop():
			return
		}
	})
}

// recursiveFindNode continues the recursive node lookup
func (d *DHT) recursiveFindNode(target rpc.NodeID, rpcID rpc.RPCID, q *rpc.Query, iter int) bool {
	// Get k-nearest nodes from routing table
	kn := d.rt.KNearest(target)

	// Filter out nodes that have already been queried
	kn = q.Filter(kn)

	// If no pending queries and no new nodes to query, we're done
	if q.Pending() == 0 && len(kn) == 0 {
		d.onFindNodeCompleted(rpcID)
		return true
	}

	// Send requests to new nodes
	for _, rt := range kn {
		d.sendFindNodeRequest(target, rpcID, rt, iter)
		q.Request(rt.NodeID) // Track that we've sent a request to this node
	}

	return false
}

// onFindNodeCompleted handles completion of a find node operation
func (d *DHT) onFindNodeCompleted(rpcID rpc.RPCID) {
	// Get and execute the completion callback
	onCompletion := d.ongoing.GetOnCompletionTask(rpcID)
	if onCompletion != nil {
		d.schedule(0, func() {
			onCompletion()
		})
	}

	// Remove the query from ongoing manager
	d.ongoing.RemoveQuery(rpcID)
}

// handleTimeout processes timeout events for pending queries
func (d *DHT) handleTimeout(timeout timeout) {
	if timeout.RPCType == rpc.RPCFindNode {
		// Increment iteration for next attempt
		iter := timeout.Iteration + 1

		// Get the query
		if q, ok := d.ongoing.GetQuery(timeout.RPCID); ok {
			// Notify query of timeout
			if q.OnTimeout(timeout.NodeID) {
				// Continue recursive lookup with next iteration
				d.recursiveFindNode(timeout.Target, timeout.RPCID, q, iter)
			}
		}
	}
}

// pingStaleRemotes sends ping messages to stale remote nodes to check liveness
func (d *DHT) pingStaleRemotes() {
	d.log.Debug("Pinging stale remotes")

	// Get list of stale remotes from routing table
	staled := d.rt.GetStaleRemote()

	// Add random jitter to pings
	ms := staledRemotePingInterval.Milliseconds()

	// Schedule pings with jitter
	for _, sr := range staled {
		remote := sr
		delay := time.Duration(rand.Uint64()%uint64(ms)) * time.Millisecond
		d.schedule(delay, func() {
			d.PingNode(network.NodeID(remote.NodeID), remote.Address)
		})
	}
}

// storeGC performs garbage collection on the key-value stores
func (d *DHT) storeGC() {
	d.log.Debug("Store GC called")
	d.store.GC()  // GC main store
	d.cached.GC() // GC cache
}

// routingTableGC performs garbage collection on the routing table
func (d *DHT) routingTableGC() {
	d.log.Debug("Routing table GC called")
	d.rt.GC() // Remove stale/unreachable nodes
}

// refillEmptyKBucket attempts to fill empty k-buckets by finding nodes
func (d *DHT) refillEmptyKBucket(noDelay bool) {
	// Rate limit refill operations
	if !d.allowToRefill() {
		return
	}

	d.log.Debug("Refilling empty k-bucket")

	// Get nodes we're interested in for empty buckets
	nodes := d.rt.InterestedNodes()

	// Add random jitter to avoid network storms
	ms := emptyKBucketRefillInterval.Milliseconds()

	// Schedule find node operations for each target
	for _, node := range nodes {
		n := node
		delay := time.Duration(rand.Uint64()%uint64(ms)) * time.Millisecond
		if noDelay {
			delay = minDelay // Use minimum delay if noDelay is true
		}
		d.schedule(delay, func() {
			d.findNode(network.NodeID(n))
		})
	}
}

// allowToJoin checks if enough time has passed since the last join
func (d *DHT) allowToJoin() bool {
	if time.Since(d.lastJoin) > minJoinInterval {
		d.lastJoin = time.Now()
		return true
	}
	return false
}

// allowToRefill checks if enough time has passed since the last refill
func (d *DHT) allowToRefill() bool {
	if time.Since(d.lastRefill) > minRefillInterval {
		d.lastRefill = time.Now()
		return true
	}
	return false
}

// schedule schedules a function to be executed on the main thread after a delay
func (d *DHT) schedule(delay time.Duration, fn schedulable) {
	d.doSchedule(delay, true, fn)
}

// runWorker runs a function in a separate goroutine after a delay
func (d *DHT) runWorker(delay time.Duration, fn schedulable) {
	d.doSchedule(delay, false, fn)
}

// doSchedule is the internal implementation for scheduling functions
func (d *DHT) doSchedule(delay time.Duration, mainThread bool, fn schedulable) {
	go func() {
		// Wait for delay if specified
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
				// Delay completed
			case <-d.stopper.ShouldStop():
				// DHT stopping, abort
				return
			}
		}

		// Execute function either on main thread or in this goroutine
		if mainThread {
			select {
			case <-d.stopper.ShouldStop():
				// DHT stopping, abort
			case d.scheduledCh <- fn:
				// Function queued for main thread
			}
		} else {
			fn() // Execute directly in this goroutine
		}
	}()
}

// findNode initiates a find node operation for a target
func (d *DHT) findNode(target network.NodeID) {
	d.doFindNode(rpc.NodeID(target), nil)
}

// verifyMessage verifies the RPC message, logging errors if invalid.
func (d *DHT) verifyMessage(msg rpc.Message) {
	// Check that sender node ID is not empty
	if network.Key(msg.From.NodeID).IsEmpty() {
		d.log.Error("Empty from node ID")
		return
	}

	// Check that RPC ID is not zero
	if msg.RPCID == 0 {
		d.log.Error("Empty RPCID")
		return
	}
}

// targetField returns a zap field for logging a target key
func (d *DHT) targetField(k network.Key) zap.Field {
	return zap.String("target", k.Short())
}

// fromField returns a zap field for logging a remote node
func (d *DHT) fromField(r rpc.Remote) zap.Field {
	return zap.String("from", network.Key(r.NodeID).Short())
}

// localNodeIDField returns a zap field for logging the local node ID
func (d *DHT) localNodeIDField() zap.Field {
	return zap.String("local", network.Key(d.self.NodeID).Short())
}

// getRandomDelay returns a random delay up to the specified duration
func getRandomDelay(d time.Duration) time.Duration {
	ms := d.Milliseconds()
	return time.Duration(rand.Uint64()%uint64(ms)) * time.Millisecond
}

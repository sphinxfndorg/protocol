package gui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind"
	"github.com/sphinxfndorg/protocol/src/network"
)

type RingLog struct {
	mu   sync.Mutex
	max  int
	data []byte
}

func NewRingLog(max int) *RingLog {
	if max < 1024 {
		max = 1024
	}
	return &RingLog{max: max}
}
func (r *RingLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = append(r.data, p...)
	if len(r.data) > r.max {
		r.data = append([]byte(nil), r.data[len(r.data)-r.max:]...)
	}
	return len(p), nil
}
func (r *RingLog) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(append([]byte(nil), r.data...))
}

type NodeConfig struct {
	DataDir  string
	Seeds    string
	Network  string
	TCPAddr  string
	UDPPort  string
	HTTPPort string
	WSPort   string
}

type EmbeddedNode struct {
	cfg  NodeConfig
	stop chan struct{}
	done chan struct{}
	err  error
	log  *RingLog
	once sync.Once
	mu   sync.Mutex
}

func DefaultNodeConfig() NodeConfig {
	home, _ := os.UserHomeDir()
	return NodeConfig{
		DataDir: filepath.Join(home, ".sphinx", "wallet-node"),
		Network: "devnet", TCPAddr: "127.0.0.1:30303", UDPPort: "30303",
		HTTPPort: "127.0.0.1:8545", WSPort: "127.0.0.1:8700",
	}
}

func (n *EmbeddedNode) Start(cfg NodeConfig) error {
	if n.done != nil {
		return errors.New("node already started")
	}
	if cfg.DataDir == "" {
		return errors.New("node data directory is required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("create node data directory: %w", err)
	}
	n.cfg, n.log = cfg, NewRingLog(256*1024)
	n.stop, n.done = make(chan struct{}), make(chan struct{})
	n.once = sync.Once{}
	portCfg := network.NodePortConfig{
		Name: "GUI", TCPAddr: cfg.TCPAddr, UDPPort: cfg.UDPPort,
		HTTPPort: cfg.HTTPPort, WSPort: cfg.WSPort, Role: network.RoleValidator,
	}
	go func() {
		err := bind.StartNodeWithOptions(cfg.DataDir, portCfg, 1, 0, nil, cfg.Network, cfg.Seeds, "",
			bind.NodeOptions{Stop: n.stop, LogWriter: n.log, DisableDashboard: true})
		n.mu.Lock()
		n.err = err
		n.mu.Unlock()
		close(n.done)
	}()
	return nil
}

func (n *EmbeddedNode) Stop(timeout time.Duration) error {
	if n.done == nil {
		return nil
	}
	n.once.Do(func() { close(n.stop) })
	select {
	case <-n.done:
		n.mu.Lock()
		err := n.err
		n.mu.Unlock()
		n.done = nil
		return err
	case <-time.After(timeout):
		return errors.New("embedded node did not stop before timeout")
	}
}
func (n *EmbeddedNode) RPCAddr() string { return n.cfg.WSPort }
func (n *EmbeddedNode) Logs() string {
	if n.log == nil {
		return ""
	}
	return n.log.String()
}
func (n *EmbeddedNode) Done() <-chan struct{} { return n.done }

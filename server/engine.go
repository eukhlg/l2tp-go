// Package server connects the L2TP wire codecs and state machines to a
// datagram-oriented server runtime.
package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"l2tp-go/protocol/l2tp"
	"l2tp-go/protocol/ppp"
)

var (
	ErrUnknownTunnel         = errors.New("l2tp server: unknown tunnel")
	ErrPeerAddress           = errors.New("l2tp server: tunnel peer address changed")
	ErrSessionNotEstablished = errors.New("l2tp server: session is not established")
)

type Config struct {
	HostName       string
	VendorName     string
	ReceiveWindow  uint16
	FirstTunnelID  uint16
	FirstSessionID uint16
}

type DataFrame struct {
	TunnelID uint16
	Session  l2tp.Session
	PPP      ppp.Frame
	Peer     net.Addr
}

type Result struct {
	Replies [][]byte
	Data    *DataFrame
}

type Datagram struct {
	Payload []byte
	Peer    net.Addr
}

type tunnelRuntime struct {
	peer    net.Addr
	state   *l2tp.ServerTunnel
	channel *l2tp.ControlChannel
}

// Engine processes complete UDP datagrams. It is safe for concurrent use.
type Engine struct {
	mu           sync.Mutex
	config       Config
	nextTunnelID uint16
	tunnels      map[uint16]*tunnelRuntime
	tunnelByPeer map[string]uint16
}

func NewEngine(config Config) *Engine {
	first := config.FirstTunnelID
	if first == 0 {
		first = 1
	}
	if config.VendorName == "" {
		config.VendorName = "l2tp-go"
	}
	return &Engine{config: config, nextTunnelID: first, tunnels: make(map[uint16]*tunnelRuntime), tunnelByPeer: make(map[string]uint16)}
}

func (e *Engine) HandleDatagram(peer net.Addr, wire []byte, now time.Time) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	packet, err := l2tp.DecodePacket(wire)
	if err != nil {
		return Result{}, err
	}
	if packet.Control {
		return e.handleControl(peer, packet, wire, now)
	}
	return e.handleData(peer, packet)
}

func (e *Engine) handleControl(peer net.Addr, packet l2tp.Packet, wire []byte, now time.Time) (Result, error) {
	runtime, created, err := e.findControlTunnel(peer, packet, wire)
	if err != nil {
		return Result{}, err
	}
	message, err := runtime.channel.Receive(wire)
	if err != nil {
		if created {
			e.removeTunnel(runtime.state.LocalTunnelID)
		}
		return Result{}, err
	}
	if message == nil {
		if len(packet.AVPs) == 0 {
			return Result{}, nil // ZLBs acknowledge; they are never acknowledged.
		}
		ack, err := runtime.channel.Ack()
		if err != nil {
			return Result{}, err
		}
		return Result{Replies: [][]byte{ack}}, nil
	}
	reply, err := runtime.state.Handle(*message)
	if err != nil {
		if created {
			e.removeTunnel(runtime.state.LocalTunnelID)
		}
		return Result{}, err
	}
	if reply != nil {
		wire, err := runtime.channel.Queue(*reply, now)
		if err != nil {
			return Result{}, err
		}
		return Result{Replies: [][]byte{wire}}, nil
	}
	ack, err := runtime.channel.Ack()
	if err != nil {
		return Result{}, err
	}
	closed := runtime.state.State == l2tp.TunnelClosed
	result := Result{Replies: [][]byte{ack}}
	if closed {
		e.removeTunnel(runtime.state.LocalTunnelID)
	}
	return result, nil
}

func (e *Engine) findControlTunnel(peer net.Addr, packet l2tp.Packet, wire []byte) (*tunnelRuntime, bool, error) {
	if packet.TunnelID != 0 {
		runtime, ok := e.tunnels[packet.TunnelID]
		if !ok {
			return nil, false, ErrUnknownTunnel
		}
		if peerKey(runtime.peer) != peerKey(peer) {
			return nil, false, ErrPeerAddress
		}
		return runtime, false, nil
	}
	if id, ok := e.tunnelByPeer[peerKey(peer)]; ok {
		return e.tunnels[id], false, nil
	}
	message, err := l2tp.DecodeControlMessage(wire)
	if err != nil {
		return nil, false, err
	}
	if message.Type != l2tp.SCCRQ {
		return nil, false, ErrUnknownTunnel
	}
	assigned, ok := message.Find(l2tp.AttrAssignedTunnelID)
	if !ok {
		return nil, false, fmt.Errorf("%w: assigned tunnel ID", l2tp.ErrMissingAttribute)
	}
	peerID, err := assigned.Uint16()
	if err != nil {
		return nil, false, err
	}
	peerWindow := uint16(1)
	if windowAVP, ok := message.Find(l2tp.AttrReceiveWindowSize); ok {
		peerWindow, err = windowAVP.Uint16()
		if err != nil {
			return nil, false, err
		}
		if peerWindow == 0 {
			return nil, false, fmt.Errorf("%w: zero receive window", l2tp.ErrInvalidAttribute)
		}
	}
	localID := e.allocateTunnelID()
	state := l2tp.NewServerTunnel(l2tp.ServerTunnelConfig{LocalTunnelID: localID, FirstSessionID: e.config.FirstSessionID, HostName: e.config.HostName, VendorName: e.config.VendorName, ReceiveWindow: e.config.ReceiveWindow})
	runtime := &tunnelRuntime{peer: peer, state: state, channel: l2tp.NewControlChannel(peerID, peerWindow)}
	e.tunnels[localID] = runtime
	e.tunnelByPeer[peerKey(peer)] = localID
	return runtime, true, nil
}

func (e *Engine) handleData(peer net.Addr, packet l2tp.Packet) (Result, error) {
	runtime, ok := e.tunnels[packet.TunnelID]
	if !ok {
		return Result{}, ErrUnknownTunnel
	}
	if peerKey(runtime.peer) != peerKey(peer) {
		return Result{}, ErrPeerAddress
	}
	session, ok := runtime.state.Session(packet.SessionID)
	if !ok || session.State != l2tp.SessionEstablished {
		return Result{}, ErrSessionNotEstablished
	}
	frame, err := ppp.DecodeFrame(packet.Payload)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: &DataFrame{TunnelID: packet.TunnelID, Session: session, PPP: frame, Peer: peer}}, nil
}

func (e *Engine) Retransmit(now time.Time, timeout time.Duration, maxRetries int) ([]Datagram, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var result []Datagram
	for _, runtime := range e.tunnels {
		packets, err := runtime.channel.Retransmit(now, timeout, maxRetries)
		if err != nil {
			return nil, err
		}
		for _, packet := range packets {
			result = append(result, Datagram{Payload: packet, Peer: runtime.peer})
		}
	}
	return result, nil
}

func (e *Engine) TunnelCount() int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.tunnels) }

func (e *Engine) allocateTunnelID() uint16 {
	for {
		id := e.nextTunnelID
		e.nextTunnelID++
		if id != 0 {
			if _, used := e.tunnels[id]; !used {
				return id
			}
		}
	}
}

func (e *Engine) removeTunnel(id uint16) {
	runtime := e.tunnels[id]
	if runtime != nil {
		delete(e.tunnelByPeer, peerKey(runtime.peer))
	}
	delete(e.tunnels, id)
}

func peerKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.Network() + "\x00" + addr.String()
}

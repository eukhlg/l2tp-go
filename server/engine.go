// Package server connects the L2TP wire codecs and state machines to a
// datagram-oriented server runtime.
package server

import (
	"errors"
	"fmt"
	"net"
	"strings"
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
	PPP            *ppp.SessionConfig
	Debugf         func(format string, args ...any)
}

type DataFrame struct {
	TunnelID uint16
	Session  l2tp.Session
	PPP      ppp.Frame
	IPv4     []byte
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
	ppp     map[uint16]*ppp.Session
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
	e.debugf("udp rx peer=%s bytes=%d", peer, len(wire))
	packet, err := l2tp.DecodePacket(wire)
	if err != nil {
		e.debugf("udp drop peer=%s decode_error=%v", peer, err)
		return Result{}, err
	}
	e.debugf("l2tp rx peer=%s control=%t tunnel=%d session=%d ns=%d nr=%d payload_bytes=%d avps=%d", peer, packet.Control, packet.TunnelID, packet.SessionID, packet.Ns, packet.Nr, len(packet.Payload), len(packet.AVPs))
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
		e.debugf("control drop peer=%s tunnel=%d error=%v", peer, runtime.state.LocalTunnelID, err)
		if created {
			e.removeTunnel(runtime.state.LocalTunnelID)
		}
		return Result{}, err
	}
	if message == nil {
		if len(packet.AVPs) == 0 {
			e.debugf("control zlb peer=%s tunnel=%d nr=%d", peer, runtime.state.LocalTunnelID, packet.Nr)
			return Result{}, nil // ZLBs acknowledge; they are never acknowledged.
		}
		ack, err := runtime.channel.Ack()
		if err != nil {
			return Result{}, err
		}
		e.debugf("control duplicate peer=%s tunnel=%d ns=%d", peer, runtime.state.LocalTunnelID, packet.Ns)
		return Result{Replies: [][]byte{ack}}, nil
	}
	stateBefore := runtime.state.State
	e.debugf("control message peer=%s type=%s tunnel=%d session=%d state=%s", peer, message.Type, message.TunnelID, message.SessionID, stateBefore)
	reply, err := runtime.state.Handle(*message)
	if err != nil {
		e.debugf("control reject peer=%s type=%s state=%s error=%v", peer, message.Type, stateBefore, err)
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
		e.debugf("control tx peer=%s type=%s local_tunnel=%d peer_tunnel=%d session=%d state=%s->%s bytes=%d", peer, reply.Type, runtime.state.LocalTunnelID, runtime.state.PeerTunnelID, reply.SessionID, stateBefore, runtime.state.State, len(wire))
		return Result{Replies: [][]byte{wire}}, nil
	}
	ack, err := runtime.channel.Ack()
	if err != nil {
		return Result{}, err
	}
	closed := runtime.state.State == l2tp.TunnelClosed
	result := Result{Replies: [][]byte{ack}}
	if message.Type == l2tp.ICCN && e.config.PPP != nil {
		session, ok := runtime.state.Session(message.SessionID)
		if !ok {
			return Result{}, l2tp.ErrUnknownSession
		}
		pppSession, err := ppp.NewSession(*e.config.PPP)
		if err != nil {
			return Result{}, err
		}
		runtime.ppp[session.LocalID] = pppSession
		e.debugf("ppp start peer=%s tunnel=%d session=%d auth=%s", peer, runtime.state.LocalTunnelID, session.LocalID, pppSession.Authentication())
		frames, err := pppSession.Start()
		if err != nil {
			return Result{}, err
		}
		for _, frame := range frames {
			wire, err := encodeDataFrame(runtime, session, frame)
			if err != nil {
				return Result{}, err
			}
			result.Replies = append(result.Replies, wire)
		}
	}
	if closed {
		e.debugf("tunnel closed peer=%s tunnel=%d", peer, runtime.state.LocalTunnelID)
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
	runtime := &tunnelRuntime{peer: peer, state: state, channel: l2tp.NewControlChannel(peerID, peerWindow), ppp: make(map[uint16]*ppp.Session)}
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
		e.debugf("ppp drop peer=%s tunnel=%d session=%d decode_error=%v", peer, packet.TunnelID, packet.SessionID, err)
		return Result{}, err
	}
	data := &DataFrame{TunnelID: packet.TunnelID, Session: session, PPP: frame, Peer: peer}
	pppSession := runtime.ppp[packet.SessionID]
	if pppSession == nil {
		return Result{Data: data}, nil
	}
	phaseBefore := pppSession.Phase
	e.debugf("ppp rx peer=%s tunnel=%d session=%d protocol=%#04x phase=%s bytes=%d", peer, packet.TunnelID, packet.SessionID, frame.Protocol, phaseBefore, len(frame.Payload))
	e.debugPPPControl("rx", peer, packet.TunnelID, packet.SessionID, frame)
	pppResult, err := pppSession.Handle(frame)
	if err != nil {
		e.debugf("ppp reject peer=%s tunnel=%d session=%d protocol=%#04x phase=%s error=%v", peer, packet.TunnelID, packet.SessionID, frame.Protocol, phaseBefore, err)
		return Result{}, err
	}
	if phaseBefore != pppSession.Phase {
		e.debugf("ppp phase peer=%s tunnel=%d session=%d %s->%s", peer, packet.TunnelID, packet.SessionID, phaseBefore, pppSession.Phase)
	}
	result := Result{}
	for _, response := range pppResult.Frames {
		wire, err := encodeDataFrame(runtime, session, response)
		if err != nil {
			return Result{}, err
		}
		result.Replies = append(result.Replies, wire)
		e.debugf("ppp tx peer=%s tunnel=%d session=%d protocol=%#04x phase=%s bytes=%d", peer, packet.TunnelID, packet.SessionID, response.Protocol, pppSession.Phase, len(response.Payload))
		e.debugPPPControl("tx", peer, packet.TunnelID, packet.SessionID, response)
	}
	if pppResult.IPv4 != nil {
		e.debugf("ipv4 routed peer=%s tunnel=%d session=%d bytes=%d", peer, packet.TunnelID, packet.SessionID, len(pppResult.IPv4))
		data.IPv4 = pppResult.IPv4
		result.Data = data
	}
	return result, nil
}

// SendIPv4 wraps an IPv4 packet for transmission to an established PPP
// session. It is used by routers to deliver return traffic to the client.
func (e *Engine) SendIPv4(tunnelID, sessionID uint16, payload []byte) (Datagram, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	runtime, ok := e.tunnels[tunnelID]
	if !ok {
		return Datagram{}, ErrUnknownTunnel
	}
	session, ok := runtime.state.Session(sessionID)
	if !ok || session.State != l2tp.SessionEstablished {
		return Datagram{}, ErrSessionNotEstablished
	}
	pppSession := runtime.ppp[sessionID]
	if pppSession == nil || pppSession.Phase != ppp.PhaseOpen {
		return Datagram{}, ErrSessionNotEstablished
	}
	wire, err := encodeDataFrame(runtime, session, ppp.Frame{Protocol: ppp.ProtocolIPv4, Payload: payload})
	if err != nil {
		return Datagram{}, err
	}
	return Datagram{Payload: wire, Peer: runtime.peer}, nil
}

func encodeDataFrame(runtime *tunnelRuntime, session l2tp.Session, frame ppp.Frame) ([]byte, error) {
	frameWire, err := frame.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return (l2tp.Packet{TunnelID: runtime.state.PeerTunnelID, SessionID: session.PeerID, Payload: frameWire}).MarshalBinary()
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

func (e *Engine) debugf(format string, args ...any) {
	if e.config.Debugf != nil {
		e.config.Debugf(format, args...)
	}
}

func (e *Engine) debugPPPControl(direction string, peer net.Addr, tunnelID, sessionID uint16, frame ppp.Frame) {
	if e.config.Debugf == nil || (frame.Protocol != ppp.ProtocolLCP && frame.Protocol != ppp.ProtocolIPCP && frame.Protocol != ppp.ProtocolCHAP) {
		return
	}
	packet, err := ppp.DecodeControlPacket(frame.Payload)
	if err != nil {
		e.debugf("ppp control %s peer=%s tunnel=%d session=%d decode_error=%v", direction, peer, tunnelID, sessionID, err)
		return
	}
	detail := fmt.Sprintf("data_bytes=%d", len(packet.Data))
	if frame.Protocol != ppp.ProtocolCHAP && packet.Code >= ppp.ConfigureRequest && packet.Code <= ppp.ConfigureReject {
		options, err := ppp.DecodeOptions(packet.Data)
		if err != nil {
			detail = fmt.Sprintf("options_error=%v", err)
		} else {
			parts := make([]string, 0, len(options))
			for _, option := range options {
				parts = append(parts, fmt.Sprintf("%d/%d", option.Type, len(option.Value)+2))
			}
			detail = "options=" + strings.Join(parts, ",")
		}
	}
	e.debugf("ppp control %s peer=%s tunnel=%d session=%d protocol=%#04x code=%s id=%d %s", direction, peer, tunnelID, sessionID, frame.Protocol, packet.Code, packet.Identifier, detail)
}

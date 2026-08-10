// Package server connects the L2TP wire codecs and state machines to a
// datagram-oriented server runtime.
package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	ErrGlobalSessionLimit    = errors.New("l2tp server: global session limit reached")
	ErrTunnelSessionLimit    = errors.New("l2tp server: tunnel session limit reached")
)

type Config struct {
	HostName             string
	VendorName           string
	ReceiveWindow        uint16
	FirstTunnelID        uint16
	FirstSessionID       uint16
	PPP                  *ppp.SessionConfig
	AddressPool          *AddressPool
	MaxSessions          int
	MaxSessionsPerTunnel int
	MaxSessionsPerUser   int
	Debugf               func(format string, args ...any)
	Tracef               func(format string, args ...any)
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
	Opened  *SessionInfo
	Closed  []SessionInfo
}

type SessionInfo struct {
	TunnelID, SessionID uint16
	Address             netip.Addr
	Peer                net.Addr
}

type Datagram struct {
	Payload []byte
	Peer    net.Addr
}

type sessionRuntime struct {
	ppp      *ppp.Session
	address  netip.Addr
	username string
	admitted bool
}

type tunnelRuntime struct {
	peer     net.Addr
	state    *l2tp.ServerTunnel
	channel  *l2tp.ControlChannel
	sessions map[uint16]*sessionRuntime
}

// Engine processes complete UDP datagrams. It is safe for concurrent use.
type Engine struct {
	mu           sync.Mutex
	config       Config
	nextTunnelID uint16
	tunnels      map[uint16]*tunnelRuntime
	tunnelByPeer map[string]uint16
	userSessions map[string]int
}

func NewEngine(config Config) *Engine {
	first := config.FirstTunnelID
	if first == 0 {
		first = 1
	}
	if config.VendorName == "" {
		config.VendorName = "l2tp-go"
	}
	return &Engine{config: config, nextTunnelID: first, tunnels: make(map[uint16]*tunnelRuntime), tunnelByPeer: make(map[string]uint16), userSessions: make(map[string]int)}
}

func (e *Engine) HandleDatagram(peer net.Addr, wire []byte, now time.Time) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tracef("udp rx peer=%s bytes=%d", peer, len(wire))
	packet, err := l2tp.DecodePacket(wire)
	if err != nil {
		e.debugf("udp drop peer=%s decode_error=%v", peer, err)
		return Result{}, err
	}
	e.tracef("l2tp rx peer=%s control=%t tunnel=%d session=%d ns=%d nr=%d payload_bytes=%d avps=%d", peer, packet.Control, packet.TunnelID, packet.SessionID, packet.Ns, packet.Nr, len(packet.Payload), len(packet.AVPs))
	if packet.Control {
		return e.handleControl(peer, packet, wire, now)
	}
	return e.handleData(peer, packet)
}

func (e *Engine) handleControl(peer net.Addr, packet l2tp.Packet, wire []byte, now time.Time) (Result, error) {
	runtime, created, replaced, err := e.findControlTunnel(peer, packet, wire)
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
			return Result{Closed: replaced}, nil // ZLBs acknowledge; they are never acknowledged.
		}
		ack, err := runtime.channel.Ack()
		if err != nil {
			return Result{}, err
		}
		e.debugf("control duplicate peer=%s tunnel=%d ns=%d", peer, runtime.state.LocalTunnelID, packet.Ns)
		return Result{Replies: [][]byte{ack}, Closed: replaced}, nil
	}
	stateBefore := runtime.state.State
	e.debugf("control message peer=%s type=%s tunnel=%d session=%d state=%s", peer, message.Type, message.TunnelID, message.SessionID, stateBefore)
	if message.Type == l2tp.ICRQ {
		if e.config.MaxSessions > 0 && e.sessionCount() >= e.config.MaxSessions {
			return e.rejectCall(runtime, *message, now, ErrGlobalSessionLimit)
		}
		if e.config.MaxSessionsPerTunnel > 0 && runtime.state.SessionCount() >= e.config.MaxSessionsPerTunnel {
			return e.rejectCall(runtime, *message, now, ErrTunnelSessionLimit)
		}
	}
	removedSessionID := uint16(0)
	if message.Type == l2tp.CDN {
		removedSessionID = message.SessionID
	}
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
		return Result{Replies: [][]byte{wire}, Closed: replaced}, nil
	}
	result := Result{Closed: replaced}
	if removedSessionID != 0 {
		if closed := e.releaseSession(runtime, removedSessionID); closed != nil {
			result.Closed = append(result.Closed, *closed)
		}
	}
	ack, err := runtime.channel.Ack()
	if err != nil {
		return Result{}, err
	}
	closed := runtime.state.State == l2tp.TunnelClosed
	result.Replies = [][]byte{ack}
	if message.Type == l2tp.ICCN && e.config.PPP != nil {
		session, ok := runtime.state.Session(message.SessionID)
		if !ok {
			return Result{}, l2tp.ErrUnknownSession
		}
		pppConfig := *e.config.PPP
		address := pppConfig.ClientAddress
		if e.config.AddressPool != nil {
			address, err = e.config.AddressPool.Acquire()
			if err != nil {
				runtime.state.RemoveSession(session.LocalID)
				return e.rejectEstablishedCall(runtime, session, now, err)
			}
			pppConfig.ClientAddress = address
		}
		sessionRuntime := &sessionRuntime{address: address}
		pppConfig.Authorize = func(username string) bool {
			if e.config.MaxSessionsPerUser > 0 && e.userSessions[username] >= e.config.MaxSessionsPerUser {
				e.debugf("session rejected tunnel=%d session=%d user=%s reason=per-user-limit current=%d limit=%d", runtime.state.LocalTunnelID, session.LocalID, username, e.userSessions[username], e.config.MaxSessionsPerUser)
				return false
			}
			e.userSessions[username]++
			sessionRuntime.username, sessionRuntime.admitted = username, true
			return true
		}
		pppSession, err := ppp.NewSession(pppConfig)
		if err != nil {
			if e.config.AddressPool != nil {
				e.config.AddressPool.Release(address)
			}
			return Result{}, err
		}
		sessionRuntime.ppp = pppSession
		runtime.sessions[session.LocalID] = sessionRuntime
		e.debugf("ppp start peer=%s tunnel=%d session=%d address=%s auth=%s", peer, runtime.state.LocalTunnelID, session.LocalID, address, pppSession.Authentication())
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
		result.Closed = append(result.Closed, e.removeTunnel(runtime.state.LocalTunnelID)...)
	}
	return result, nil
}

func (e *Engine) rejectCall(runtime *tunnelRuntime, message l2tp.ControlMessage, now time.Time, reason error) (Result, error) {
	assigned, ok := message.Find(l2tp.AttrAssignedSessionID)
	if !ok {
		return Result{}, reason
	}
	peerSessionID, err := assigned.Uint16()
	if err != nil {
		return Result{}, err
	}
	return e.queueCallRejection(runtime, peerSessionID, now, reason)
}

func (e *Engine) rejectEstablishedCall(runtime *tunnelRuntime, session l2tp.Session, now time.Time, reason error) (Result, error) {
	return e.queueCallRejection(runtime, session.PeerID, now, reason)
}

func (e *Engine) queueCallRejection(runtime *tunnelRuntime, peerSessionID uint16, now time.Time, reason error) (Result, error) {
	message := l2tp.ControlMessage{Type: l2tp.CDN, SessionID: peerSessionID, AVPs: []l2tp.AVP{l2tp.Uint16AVP(l2tp.AttrResultCode, 4, true)}}
	wire, err := runtime.channel.Queue(message, now)
	if err != nil {
		return Result{}, err
	}
	e.debugf("session rejected tunnel=%d peer_session=%d reason=%v", runtime.state.LocalTunnelID, peerSessionID, reason)
	return Result{Replies: [][]byte{wire}}, nil
}

func (e *Engine) findControlTunnel(peer net.Addr, packet l2tp.Packet, wire []byte) (*tunnelRuntime, bool, []SessionInfo, error) {
	if packet.TunnelID != 0 {
		runtime, ok := e.tunnels[packet.TunnelID]
		if !ok {
			return nil, false, nil, ErrUnknownTunnel
		}
		if peerKey(runtime.peer) != peerKey(peer) {
			return nil, false, nil, ErrPeerAddress
		}
		return runtime, false, nil, nil
	}
	message, err := l2tp.DecodeControlMessage(wire)
	if err != nil {
		return nil, false, nil, err
	}
	if message.Type != l2tp.SCCRQ {
		return nil, false, nil, ErrUnknownTunnel
	}
	if message.Ns != 0 || message.Nr != 0 {
		return nil, false, nil, fmt.Errorf("%w: fresh SCCRQ requires Ns=0 and Nr=0", l2tp.ErrUnexpectedMessage)
	}
	assigned, ok := message.Find(l2tp.AttrAssignedTunnelID)
	if !ok {
		return nil, false, nil, fmt.Errorf("%w: assigned tunnel ID", l2tp.ErrMissingAttribute)
	}
	peerID, err := assigned.Uint16()
	if err != nil {
		return nil, false, nil, err
	}
	peerWindow := uint16(1)
	if windowAVP, ok := message.Find(l2tp.AttrReceiveWindowSize); ok {
		peerWindow, err = windowAVP.Uint16()
		if err != nil {
			return nil, false, nil, err
		}
		if peerWindow == 0 {
			return nil, false, nil, fmt.Errorf("%w: zero receive window", l2tp.ErrInvalidAttribute)
		}
	}
	probe := l2tp.NewServerTunnel(l2tp.ServerTunnelConfig{LocalTunnelID: 1, HostName: e.config.HostName, VendorName: e.config.VendorName, ReceiveWindow: e.config.ReceiveWindow})
	if _, err := probe.Handle(message); err != nil {
		return nil, false, nil, err
	}
	var replaced []SessionInfo
	if id, ok := e.tunnelByPeer[peerKey(peer)]; ok {
		runtime := e.tunnels[id]
		if runtime != nil && runtime.state.State != l2tp.TunnelEstablished && runtime.state.PeerTunnelID == peerID {
			return runtime, false, nil, nil
		}
		e.debugf("control restart peer=%s replacing_tunnel=%d", peer, id)
		replaced = e.removeTunnel(id)
	}
	localID := e.allocateTunnelID()
	state := l2tp.NewServerTunnel(l2tp.ServerTunnelConfig{LocalTunnelID: localID, FirstSessionID: e.config.FirstSessionID, HostName: e.config.HostName, VendorName: e.config.VendorName, ReceiveWindow: e.config.ReceiveWindow})
	runtime := &tunnelRuntime{peer: peer, state: state, channel: l2tp.NewControlChannel(peerID, peerWindow), sessions: make(map[uint16]*sessionRuntime)}
	e.tunnels[localID] = runtime
	e.tunnelByPeer[peerKey(peer)] = localID
	return runtime, true, replaced, nil
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
	sessionRuntime := runtime.sessions[packet.SessionID]
	if sessionRuntime == nil || sessionRuntime.ppp == nil {
		return Result{Data: data}, nil
	}
	pppSession := sessionRuntime.ppp
	phaseBefore := pppSession.Phase
	e.tracef("ppp rx peer=%s tunnel=%d session=%d protocol=%#04x phase=%s bytes=%d", peer, packet.TunnelID, packet.SessionID, frame.Protocol, phaseBefore, len(frame.Payload))
	e.debugPPPControl("rx", peer, packet.TunnelID, packet.SessionID, frame)
	pppResult, err := pppSession.Handle(frame)
	if err != nil {
		e.debugf("ppp reject peer=%s tunnel=%d session=%d protocol=%#04x phase=%s error=%v", peer, packet.TunnelID, packet.SessionID, frame.Protocol, phaseBefore, err)
		return Result{}, err
	}
	var closedInfo *SessionInfo
	if pppSession.Phase == ppp.PhaseClosed {
		closedInfo = e.releaseSession(runtime, packet.SessionID)
	}
	if phaseBefore != pppSession.Phase {
		e.debugf("ppp phase peer=%s tunnel=%d session=%d %s->%s", peer, packet.TunnelID, packet.SessionID, phaseBefore, pppSession.Phase)
	}
	result := Result{}
	if closedInfo != nil {
		result.Closed = append(result.Closed, *closedInfo)
	}
	if phaseBefore != ppp.PhaseOpen && pppSession.Phase == ppp.PhaseOpen {
		result.Opened = &SessionInfo{TunnelID: packet.TunnelID, SessionID: packet.SessionID, Address: sessionRuntime.address, Peer: peer}
	}
	for _, response := range pppResult.Frames {
		wire, err := encodeDataFrame(runtime, session, response)
		if err != nil {
			return Result{}, err
		}
		result.Replies = append(result.Replies, wire)
		e.tracef("ppp tx peer=%s tunnel=%d session=%d protocol=%#04x phase=%s bytes=%d", peer, packet.TunnelID, packet.SessionID, response.Protocol, pppSession.Phase, len(response.Payload))
		e.debugPPPControl("tx", peer, packet.TunnelID, packet.SessionID, response)
	}
	if pppResult.IPv4 != nil {
		e.tracef("ipv4 routed peer=%s tunnel=%d session=%d bytes=%d", peer, packet.TunnelID, packet.SessionID, len(pppResult.IPv4))
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
	sessionRuntime := runtime.sessions[sessionID]
	if sessionRuntime == nil || sessionRuntime.ppp == nil || sessionRuntime.ppp.Phase != ppp.PhaseOpen {
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

// Shutdown creates a final StopCCN for every live tunnel and releases all
// local session resources. The packets are intentionally not retained for
// retransmission because the process is terminating.
func (e *Engine) Shutdown() ([]Datagram, []SessionInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var packets []Datagram
	var closed []SessionInfo
	for id, runtime := range e.tunnels {
		message := l2tp.ControlMessage{Type: l2tp.StopCCN, AVPs: []l2tp.AVP{
			l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, runtime.state.LocalTunnelID, true),
			l2tp.Uint16AVP(l2tp.AttrResultCode, 6, true),
		}}
		wire, err := runtime.channel.QueueUntracked(message)
		if err != nil {
			return packets, closed, err
		}
		packets = append(packets, Datagram{Payload: wire, Peer: runtime.peer})
		closed = append(closed, e.removeTunnel(id)...)
		e.debugf("tunnel shutdown peer=%s tunnel=%d", runtime.peer, id)
	}
	return packets, closed, nil
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

func (e *Engine) removeTunnel(id uint16) []SessionInfo {
	runtime := e.tunnels[id]
	var closed []SessionInfo
	if runtime != nil {
		for sessionID := range runtime.sessions {
			if info := e.releaseSession(runtime, sessionID); info != nil {
				closed = append(closed, *info)
			}
		}
		delete(e.tunnelByPeer, peerKey(runtime.peer))
	}
	delete(e.tunnels, id)
	return closed
}

func (e *Engine) sessionCount() int {
	total := 0
	for _, runtime := range e.tunnels {
		total += runtime.state.SessionCount()
	}
	return total
}

func (e *Engine) releaseSession(runtime *tunnelRuntime, sessionID uint16) *SessionInfo {
	session := runtime.sessions[sessionID]
	if session == nil {
		return nil
	}
	if e.config.AddressPool != nil {
		e.config.AddressPool.Release(session.address)
	}
	if session.admitted && e.userSessions[session.username] > 0 {
		e.userSessions[session.username]--
		if e.userSessions[session.username] == 0 {
			delete(e.userSessions, session.username)
		}
	}
	delete(runtime.sessions, sessionID)
	runtime.state.RemoveSession(sessionID)
	e.debugf("ppp released tunnel=%d session=%d address=%s user=%s", runtime.state.LocalTunnelID, sessionID, session.address, session.username)
	return &SessionInfo{TunnelID: runtime.state.LocalTunnelID, SessionID: sessionID, Address: session.address, Peer: runtime.peer}
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

func (e *Engine) tracef(format string, args ...any) {
	if e.config.Tracef != nil {
		e.config.Tracef(format, args...)
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
	codeName := packet.Code.String()
	if frame.Protocol == ppp.ProtocolCHAP {
		switch packet.Code {
		case 1:
			codeName = "Challenge"
		case 2:
			codeName = "Response"
		case 3:
			codeName = "Success"
		case 4:
			codeName = "Failure"
		}
	}
	e.debugf("ppp control %s peer=%s tunnel=%d session=%d protocol=%#04x code=%s id=%d %s", direction, peer, tunnelID, sessionID, frame.Protocol, codeName, packet.Identifier, detail)
}

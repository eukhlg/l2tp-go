package server

import (
	"net"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

// BatchPacketConn is an optional outer-UDP capability, not a delivery interface:
// batched reads into netio messages. Only entries in the returned prefix are
// valid; truncated messages are never passed to the protocol engine.
// Implementations preserve boundaries and the PacketConn deadline/close
// contract, and must not replace a message's Payload. UDPTransport implements it.
type BatchPacketConn interface {
	net.PacketConn
	BatchSize() int
	ReadBatch([]udptransport.Message) (int, error)
}

// OwnedPacketWriter consumes buffer on every outcome. Accepted buffers stay
// alive through final send/rejection; eligible must be rechecked before sending.
type OwnedPacketWriter interface {
	WritePacket(*packetbuf.Buffer, net.Addr, func() bool) error
}
type SessionDatagramWriter interface {
	WriteSessionPacket([]byte, net.Addr, func() bool) error
}

// FlowPacketWriter is OwnedPacketWriter with a flow key, for transports that
// spread sends over shards. Datagrams with equal flow keys keep their order.
type FlowPacketWriter interface {
	WriteFlowPacket(*packetbuf.Buffer, net.Addr, func() bool, uint32) error
}

// SessionEligibility captures the current tunnel and PPP session identity.
// The returned check rejects closed or replaced sessions even after numeric ID
// reuse. It is safe to call from an asynchronous delivery consumer.
func (e *Engine) SessionEligibility(tunnelID, sessionID uint16) func() bool {
	return e.sendEligibility(tunnelID, sessionID)
}

// sendEligibility pins identity, not only numeric IDs, so an old writer cannot
// send through a closed/replaced session even if its IDs have been reused. It
// reads the session's sendable flag without locking: the flag is cleared under
// Engine.mu before a session is released, and numeric IDs are reused only after
// that release, so the captured runtime answers for exactly one session.
func (e *Engine) sendEligibility(tunnelID, sessionID uint16) func() bool {
	e.mu.Lock()
	var session *sessionRuntime
	if tunnel := e.tunnels[tunnelID]; tunnel != nil {
		session = tunnel.sessions[sessionID]
	}
	e.mu.Unlock()
	if session == nil {
		return func() bool { return false }
	}
	return session.sendable.Load
}

// SessionFramer frames IPv4 for one established session without taking the
// Engine lock per packet. The peer IDs and outer address are fixed for the
// session's life; Sendable turns false for good once the session closes.
type SessionFramer struct {
	session                 *sessionRuntime
	peer                    net.Addr
	peerTunnel, peerSession uint16
}

// SessionFramer captures the framing context of an established session.
func (e *Engine) SessionFramer(tunnelID, sessionID uint16) (*SessionFramer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	runtime, ok := e.tunnels[tunnelID]
	if !ok {
		return nil, ErrUnknownTunnel
	}
	state, ok := runtime.state.Session(sessionID)
	session := runtime.sessions[sessionID]
	if !ok || state.State != l2tp.SessionEstablished || session == nil || !session.sendable.Load() {
		return nil, ErrSessionNotEstablished
	}
	return &SessionFramer{session: session, peer: runtime.peer, peerTunnel: runtime.state.PeerTunnelID, peerSession: state.PeerID}, nil
}

// Sendable reports whether the session is still established and PPP open.
func (f *SessionFramer) Sendable() bool { return f.session.sendable.Load() }

// Peer returns the session's outer UDP address. Callers must not modify it.
func (f *SessionFramer) Peer() net.Addr { return f.peer }

// PrependIPv4 adds the PPP and L2TP data headers in front of buffer's IPv4.
func (f *SessionFramer) PrependIPv4(buffer *packetbuf.Buffer) error {
	if !f.session.sendable.Load() {
		return ErrSessionNotEstablished
	}
	if err := ppp.PrependFrame(buffer, ppp.ProtocolIPv4); err != nil {
		return err
	}
	return l2tp.PrependData(buffer, f.peerTunnel, f.peerSession)
}

// OwnedWriter returns a per-session plaintext writer consuming each buffer.
// It preserves individual framing and UDP datagrams; delivery to TUN is unrelated.
func (s *Server) OwnedWriter(tunnelID, sessionID uint16) func(*packetbuf.Buffer) error {
	eligible := s.Engine.sendEligibility(tunnelID, sessionID)
	return func(buffer *packetbuf.Buffer) error {
		s.sendMu.Lock()
		defer s.sendMu.Unlock()
		if !eligible() {
			buffer.Release()
			return ErrSessionNotEstablished
		}
		peer, err := s.Engine.PrependIPv4(tunnelID, sessionID, buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		if writer, ok := s.Conn.(OwnedPacketWriter); ok {
			return writer.WritePacket(buffer, peer, eligible)
		}
		defer buffer.Release()
		_, err = s.Conn.WriteTo(buffer.Bytes(), peer)
		return err
	}
}

// OwnedFlowWriter is OwnedWriter for sharded transports: it frames with a
// SessionFramer, without the Engine or send locks per packet, and passes flow
// (an inner flow hash) on, so one flow keeps its order on a sharded sender.
// Ownership: every buffer is consumed on every outcome; once a transport
// accepts it, that transport releases it exactly once after the write.
// Data and control messages use independent L2TP channels, so data needs no
// ordering against control sends; a closed session stops data via Sendable.
func (s *Server) OwnedFlowWriter(tunnelID, sessionID uint16) func(*packetbuf.Buffer, uint32) error {
	framer, framerErr := s.Engine.SessionFramer(tunnelID, sessionID)
	if framerErr != nil {
		return func(buffer *packetbuf.Buffer, _ uint32) error {
			buffer.Release()
			return framerErr
		}
	}
	eligible := framer.Sendable
	flowWriter, _ := s.Conn.(FlowPacketWriter)
	ownedWriter, _ := s.Conn.(OwnedPacketWriter)
	return func(buffer *packetbuf.Buffer, flow uint32) error {
		if err := framer.PrependIPv4(buffer); err != nil {
			buffer.Release()
			return err
		}
		switch {
		case flowWriter != nil:
			return flowWriter.WriteFlowPacket(buffer, framer.peer, eligible, flow)
		case ownedWriter != nil:
			return ownedWriter.WritePacket(buffer, framer.peer, eligible)
		}
		defer buffer.Release()
		_, err := s.Conn.WriteTo(buffer.Bytes(), framer.peer)
		return err
	}
}

// SessionBindingGuard captures a session identity for delayed route publication.
// The returned guard runs a short callback while excluding Engine teardown and
// ID reuse. The callback must not call the Engine or perform device/socket I/O.
func (e *Engine) SessionBindingGuard(tunnelID, sessionID uint16) func(func()) bool {
	e.mu.Lock()
	tunnel := e.tunnels[tunnelID]
	var session *sessionRuntime
	if tunnel != nil {
		session = tunnel.sessions[sessionID]
	}
	e.mu.Unlock()
	return func(f func()) bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		current := e.tunnels[tunnelID]
		if tunnel == nil || session == nil || current != tunnel || current.sessions[sessionID] != session || session.ppp == nil || session.ppp.Phase != ppp.PhaseOpen {
			return false
		}
		state, ok := current.state.Session(sessionID)
		if !ok || state.State != l2tp.SessionEstablished {
			return false
		}
		f()
		return true
	}
}

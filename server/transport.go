package server

import (
	"net"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
)

// ReceivedDatagram is one socket message. Only entries in the returned prefix
// are valid. Truncated messages must never be passed to the protocol engine.
type ReceivedDatagram struct {
	Payload   []byte
	N         int
	Peer      net.Addr
	Truncated bool
}

// BatchPacketConn is an optional outer-UDP capability, not a delivery interface.
// Implementations preserve boundaries and retain the PacketConn deadline/close contract.
type BatchPacketConn interface {
	net.PacketConn
	BatchSize() int
	ReadBatch([]ReceivedDatagram) (int, error)
}
type ReceiveBuffer interface {
	Bytes() []byte
	Release()
}
type ReceiveBufferAllocator interface{ AcquireReceiveBuffer() (ReceiveBuffer, error) }
type OwnedPacketBuffer interface {
	HeaderBuffer
	ReceiveBuffer
}

// OwnedPacketWriter consumes buffer on every outcome. Accepted buffers stay
// alive through final send/rejection; eligible must be rechecked before sending.
type OwnedPacketWriter interface {
	WritePacket(OwnedPacketBuffer, net.Addr, func() bool) error
}
type SessionDatagramWriter interface {
	WriteSessionPacket([]byte, net.Addr, func() bool) error
}

type heapReceiveBuffer []byte

func (b heapReceiveBuffer) Bytes() []byte { return b }
func (b heapReceiveBuffer) Release()      { clear(b) }

// SessionEligibility captures the current tunnel and PPP session identity.
// The returned check rejects closed or replaced sessions even after numeric ID
// reuse. It is safe to call from an asynchronous delivery consumer.
func (e *Engine) SessionEligibility(tunnelID, sessionID uint16) func() bool {
	return e.sendEligibility(tunnelID, sessionID)
}

// sendEligibility pins identity, not only numeric IDs, so an old writer cannot
// send through a closed/replaced session even if its IDs have been reused.
func (e *Engine) sendEligibility(tunnelID, sessionID uint16) func() bool {
	e.mu.Lock()
	tunnel := e.tunnels[tunnelID]
	var session *sessionRuntime
	if tunnel != nil {
		session = tunnel.sessions[sessionID]
	}
	e.mu.Unlock()
	return func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		current := e.tunnels[tunnelID]
		if tunnel == nil || session == nil || current != tunnel || current.sessions[sessionID] != session || session.ppp == nil || session.ppp.Phase != ppp.PhaseOpen {
			return false
		}
		state, ok := current.state.Session(sessionID)
		return ok && state.State == l2tp.SessionEstablished
	}
}

// OwnedWriter returns a per-session plaintext writer consuming each buffer.
// It preserves individual framing and UDP datagrams; delivery to TUN is unrelated.
func (s *Server) OwnedWriter(tunnelID, sessionID uint16) func(OwnedPacketBuffer) error {
	eligible := s.Engine.sendEligibility(tunnelID, sessionID)
	return func(buffer OwnedPacketBuffer) error {
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

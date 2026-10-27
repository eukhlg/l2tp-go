package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
)

type DataHandler func(context.Context, DataFrame) error

// PacketWriter sends one raw IPv4 packet back to the PPP session associated
// with an event. Embedders can retain it for the lifetime of that session.
type PacketWriter func([]byte) error

// IPv4Router accepts a packet from a client. The send callback may be used
// synchronously to route zero or more return packets to that same PPP session.
type IPv4Router func(context.Context, DataFrame, PacketWriter) error

// OwnedIPv4Router borrows storage until the driver's batch flush returns.
// frame.IPv4 starts at offset in storage; the driver retains ownership.
type OwnedIPv4Router func(context.Context, DataFrame, []byte, int, PacketWriter) error

type SessionOpenHandler func(context.Context, SessionInfo, PacketWriter) error
type SessionCloseHandler func(context.Context, SessionInfo)

type Server struct {
	// ReceivePipeline separates socket reads, ordered Engine processing, and
	// route flush into three stages joined by bounded queues. Default off.
	// NewRouteBatch must return independent state on every call when enabled.
	ReceivePipeline bool

	// Plain receive caches one packet writer per session (invalidated when the
	// session opens or closes) instead of building one per data packet.
	writersMu sync.Mutex
	writers   map[writerKey]cachedWriter
	// plainWrite is s.writeConn bound once, so dispatch does not allocate a
	// method value per datagram.
	plainWrite SessionPacketWriter

	// BorrowedReceive opts callbacks into synchronous borrowed packet views.
	// Copy payloads before retaining them beyond callback/dispatch return.
	BorrowedReceive bool
	sendMu          sync.Mutex
	Conn            net.PacketConn
	Engine          *Engine
	HandleData      DataHandler
	RouteIPv4       IPv4Router
	RouteIPv4Owned  OwnedIPv4Router
	// ReceiveHeadroom reserves bytes before each datagram in Serve's receive
	// buffers, for owned routers that prepend metadata in place (for example a
	// TUN virtio header). Zero by default; at most 64.
	ReceiveHeadroom int
	// NewRouteBatch creates private state for one receive envelope; Serve
	// reuses it for every batch that envelope carries. Flush must run
	// before receive storage is cleared, reused or released, including on errors.
	NewRouteBatch     func(context.Context) (context.Context, func() error)
	SessionOpened     SessionOpenHandler
	SessionClosed     SessionCloseHandler
	RetransmitTimeout time.Duration
	MaxRetries        int
}

// Listen creates an L2TP UDP listener. Standard L2TP uses address ":1701".
func Listen(address string, config Config) (*Server, error) {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	return New(conn, config)
}

// New creates an L2TP server over a caller-owned packet connection. This is
// the preferred constructor for embedding in another network service. Close
// closes conn; callers that share a connection should pass a dedicated wrapper.
func New(conn net.PacketConn, config Config) (*Server, error) {
	if conn == nil {
		return nil, errors.New("l2tp server: packet connection is required")
	}
	return &Server{Conn: conn, Engine: NewEngine(config), RetransmitTimeout: time.Second, MaxRetries: 5}, nil
}

// Serve runs until the context is cancelled, the connection is closed, or a
// data handler returns an error. Tunnel-specific protocol failures are isolated
// to the affected tunnel. The caller remains responsible for Close.
func (s *Server) Serve(ctx context.Context) error {
	if s.Conn == nil || s.Engine == nil {
		return errors.New("l2tp server: Conn and Engine are required")
	}
	tick := s.RetransmitTimeout / 2
	if tick <= 0 {
		tick = 500 * time.Millisecond
	}
	size := 1
	batch, batched := s.Conn.(BatchPacketConn)
	if batched {
		size = batch.BatchSize()
		if size < 1 || size > 256 {
			return errors.New("l2tp server: invalid socket batch size")
		}
	}
	headroom := s.ReceiveHeadroom
	if headroom < 0 || headroom > 64 {
		return errors.New("l2tp server: receive headroom must be between 0 and 64")
	}
	s.plainWrite = s.writeConn
	if s.ReceivePipeline {
		return s.servePipeline(ctx, size, headroom, tick, batch, batched)
	}
	pool := s.newReadBatchPool(ctx, size, headroom, 1)
	defer pool.close()
	// Wake a read on cancellation and bound an in-flight/queued socket write.
	// This watcher never closes the socket before best-effort StopCCN publication.
	watcherDone, stopWatcher := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = s.Conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
			_ = s.Conn.SetReadDeadline(time.Now())
		case <-stopWatcher:
		}
	}()
	defer func() { close(stopWatcher); <-watcherDone }()
	for {
		if ctx.Err() != nil {
			return s.cancelShutdown(ctx)
		}
		if err := s.Conn.SetReadDeadline(time.Now().Add(tick)); err != nil {
			return err
		}
		received, err := pool.acquire()
		if err != nil {
			if ctx.Err() != nil {
				return s.cancelShutdown(ctx)
			}
			return err
		}
		count, err := received.read(s.Conn, batch, batched)
		handleErr := func() (handleErr error) {
			defer pool.recycle(received)
			defer func() {
				if flushErr := received.flush(); handleErr == nil {
					handleErr = flushErr
				}
			}()
			if count < 0 || count > len(received.messages) {
				return io.ErrUnexpectedEOF
			}
			return s.processReadBatch(received, count)
		}()
		if ctx.Err() != nil {
			return s.cancelShutdown(ctx)
		}
		if handleErr != nil {
			return handleErr
		}
		if err != nil {
			if ctx.Err() != nil {
				return s.cancelShutdown(ctx)
			}
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				return err
			}
		} else if count == 0 {
			return io.ErrNoProgress
		}
		if err := s.retransmit(ctx); err != nil {
			if ctx.Err() != nil {
				return s.cancelShutdown(ctx)
			}
			return err
		}
	}
}

func (s *Server) processDatagram(ctx context.Context, peer net.Addr, wire []byte) error {
	// Receiving data/ACKs must not wait behind outbound queue backpressure.
	result, err := s.Engine.HandleDatagramBorrowed(peer, wire, time.Now())
	if err == nil && len(result.Replies) > 0 {
		s.sendMu.Lock()
		for _, reply := range result.Replies {
			if _, err = s.Conn.WriteTo(reply, peer); err != nil {
				break
			}
			s.Engine.tracef("udp tx peer=%s bytes=%d", peer, len(reply))
		}
		s.sendMu.Unlock()
	}
	if err != nil {
		// Protocol failures are peer-local; socket failures are terminal.
		if len(result.Replies) > 0 {
			return err
		}
		if errors.Is(err, ErrNewTunnelRateLimited) {
			s.Engine.tracef("datagram rate limited peer=%s", peer)
			return nil
		}
		if errors.Is(err, ErrUnknownTunnel) && isTeardownControlDatagram(wire) {
			return nil
		}
		s.Engine.debugf("datagram rejected peer=%s error=%v", peer, err)
		return nil
	}
	copyBorrowed := false
	if !s.BorrowedReceive && result.Data != nil && s.RouteIPv4Owned != nil {
		// The owned router keeps the borrowed frame; legacy consumers still get
		// independent copies, made only where they are used.
		copyBorrowed = true
	} else if !s.BorrowedReceive && result.Data != nil {
		// Preserve legacy callbacks' independently owned result semantics.
		result.Data.PPP.Payload = append([]byte(nil), result.Data.PPP.Payload...)
		if result.Data.IPv4 != nil {
			result.Data.IPv4 = append([]byte(nil), result.Data.IPv4...)
		}
	}
	return s.dispatchPlain(ctx, result, copyBorrowed)
}

type writerKey struct{ tunnelID, sessionID uint16 }
type cachedWriter struct {
	peer   net.Addr
	writer PacketWriter
}

func (s *Server) writeConn(peer net.Addr, _, _ uint16, payload []byte) error {
	_, err := s.Conn.WriteTo(payload, peer)
	return err
}

// dispatchPlain is dispatch for Serve's own datagrams, reusing session writers.
func (s *Server) dispatchPlain(ctx context.Context, result Result, copyBorrowed bool) error {
	write := s.plainWrite
	if write == nil {
		write = s.writeConn
	}
	return s.dispatchWith(ctx, result, "l2tp", write, false, copyBorrowed, true)
}

// plainWriter returns the cached writer for a session, building it on a miss.
func (s *Server) plainWriter(peer net.Addr, tunnelID, sessionID uint16) PacketWriter {
	key := writerKey{tunnelID, sessionID}
	s.writersMu.Lock()
	defer s.writersMu.Unlock()
	if c, ok := s.writers[key]; ok && samePeer(c.peer, peer) {
		return c.writer
	}
	write := s.plainWrite
	if write == nil {
		write = s.writeConn
	}
	w := s.makeWriter("l2tp", write, false, peer, tunnelID, sessionID)
	if s.writers == nil {
		s.writers = make(map[writerKey]cachedWriter)
	}
	s.writers[key] = cachedWriter{peer, w}
	return w
}

func (s *Server) forgetWriter(tunnelID, sessionID uint16) {
	s.writersMu.Lock()
	delete(s.writers, writerKey{tunnelID, sessionID})
	s.writersMu.Unlock()
}
func (s *Server) retransmit(ctx context.Context) error {
	s.sendMu.Lock()
	packets, closed, err := s.Engine.Retransmit(time.Now(), s.RetransmitTimeout, s.MaxRetries)
	if err == nil {
		for _, packet := range packets {
			if _, err = s.Conn.WriteTo(packet.Payload, packet.Peer); err != nil {
				break
			}
		}
	}
	s.sendMu.Unlock()
	if s.SessionClosed != nil {
		for _, info := range closed {
			info.Protocol = "l2tp"
			s.SessionClosed(ctx, info)
		}
	}
	return err
}
func (s *Server) cancelShutdown(ctx context.Context) error {
	err := s.gracefulShutdown(ctx)
	if err != nil {
		var ne net.Error
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) && !(errors.As(err, &ne) && ne.Timeout()) {
			return err
		}
	}
	return nil
}

// SessionPacketWriter is the transport-specific final step used by Dispatch.
// The engine has already selected the logical L2TP session; the implementation
// only needs to wrap and transmit the resulting L2TP datagram.
type SessionPacketWriter func(peer net.Addr, tunnelID, sessionID uint16, payload []byte) error

// Dispatch publishes an engine result through the server callbacks. It is
// shared by raw L2TP and protected L2TP/IPsec transports so embedders observe a
// single session and raw-IPv4 API independent of the outer transport.
func (s *Server) Dispatch(ctx context.Context, result Result, protocol string, write SessionPacketWriter) error {
	return s.dispatchWith(ctx, result, protocol, write, false, false, false)
}

// DispatchIPv4 lets an embedder frame IPv4 directly into owned storage. The
// writer receives caller-owned IPv4 and must copy it before retaining it.
func (s *Server) DispatchIPv4(ctx context.Context, result Result, protocol string, write SessionPacketWriter) error {
	return s.dispatchWith(ctx, result, protocol, write, true, false, false)
}

// makeWriter builds a session packet writer. For plain L2TP it captures the
// session's identity, so it rejects sends once that session is gone.
func (s *Server) makeWriter(protocol string, write SessionPacketWriter, ipv4 bool, peer net.Addr, tunnelID, sessionID uint16) PacketWriter {
	var eligible func() bool
	if protocol == "l2tp" {
		eligible = s.Engine.sendEligibility(tunnelID, sessionID)
	}
	return func(payload []byte) error {
		if protocol == "l2tp" {
			s.sendMu.Lock()
			defer s.sendMu.Unlock()
			if !eligible() {
				return ErrSessionNotEstablished
			}
		}
		if ipv4 {
			return write(peer, tunnelID, sessionID, payload)
		}
		packet, err := s.Engine.SendIPv4(tunnelID, sessionID, payload)
		if err != nil {
			return err
		}
		if protocol == "l2tp" {
			if sender, ok := s.Conn.(SessionDatagramWriter); ok {
				return sender.WriteSessionPacket(packet.Payload, packet.Peer, eligible)
			}
		}
		return write(peer, tunnelID, sessionID, packet.Payload)
	}
}

// copyBorrowed gives HandleData and the RouteIPv4 fallback independent copies
// of a borrowed frame while the owned router keeps the original. cached reuses
// per-session writers; only Serve's own datagrams (fixed protocol and write) use it.
func (s *Server) dispatchWith(ctx context.Context, result Result, protocol string, write SessionPacketWriter, ipv4, copyBorrowed, cached bool) error {
	if s.Engine == nil || write == nil {
		return errors.New("l2tp server: engine and packet writer are required")
	}
	newWriter := func(peer net.Addr, tunnelID, sessionID uint16) PacketWriter {
		if cached {
			return s.plainWriter(peer, tunnelID, sessionID)
		}
		return s.makeWriter(protocol, write, ipv4, peer, tunnelID, sessionID)
	}
	if cached {
		if result.Opened != nil {
			s.forgetWriter(result.Opened.TunnelID, result.Opened.SessionID)
		}
		for _, info := range result.Closed {
			s.forgetWriter(info.TunnelID, info.SessionID)
		}
	}
	if result.Opened != nil && s.SessionOpened != nil {
		info := *result.Opened
		info.Protocol = protocol
		if err := s.SessionOpened(ctx, info, newWriter(info.Peer, info.TunnelID, info.SessionID)); err != nil {
			return err
		}
	}
	if s.SessionClosed != nil {
		for _, info := range result.Closed {
			info.Protocol = protocol
			s.SessionClosed(ctx, info)
		}
	}
	var owned *DataFrame
	independent := func() DataFrame {
		if owned == nil {
			frame := *result.Data
			frame.PPP.Payload = append([]byte(nil), frame.PPP.Payload...)
			if frame.IPv4 != nil {
				frame.IPv4 = append([]byte(nil), frame.IPv4...)
			}
			owned = &frame
		}
		return *owned
	}
	if result.Data != nil && s.HandleData != nil {
		data := *result.Data
		if copyBorrowed {
			data = independent()
		}
		if err := s.HandleData(ctx, data); err != nil {
			return err
		}
	}
	if result.Data != nil && result.Data.IPv4 != nil && s.RouteIPv4Owned != nil {
		frame := *result.Data
		storage, offset, ok := packetStorage(ctx, frame.IPv4)
		if ok {
			return s.RouteIPv4Owned(ctx, frame, storage, offset, newWriter(frame.Peer, frame.TunnelID, frame.Session.LocalID))
		}
	}
	if result.Data != nil && result.Data.IPv4 != nil && s.RouteIPv4 != nil {
		frame := *result.Data
		if copyBorrowed {
			frame = independent()
		}
		if err := s.RouteIPv4(ctx, frame, newWriter(frame.Peer, frame.TunnelID, frame.Session.LocalID)); err != nil {
			return err
		}
	}
	return nil
}

func isTeardownControlDatagram(wire []byte) bool {
	message, err := l2tp.DecodeControlMessage(wire)
	return err == nil && (message.Type == l2tp.CDN || message.Type == l2tp.StopCCN)
}

func (s *Server) gracefulShutdown(ctx context.Context) error {
	s.sendMu.Lock()
	packets, closed, err := s.Engine.Shutdown()
	if err == nil {
		for _, packet := range packets {
			if _, err = s.Conn.WriteTo(packet.Payload, packet.Peer); err != nil {
				break
			}
			s.Engine.debugf("udp tx shutdown peer=%s bytes=%d", packet.Peer, len(packet.Payload))
		}
	}
	s.sendMu.Unlock()
	if s.SessionClosed != nil {
		for _, info := range closed {
			info.Protocol = "l2tp"
			s.SessionClosed(ctx, info)
		}
	}
	return err
}

func (s *Server) Close() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}

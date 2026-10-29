package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

type receiveBatchConn struct {
	packets []udptransport.Message
	reads   int
	events  *[]string
}

func (c *receiveBatchConn) BatchSize() int { return 8 }
func (c *receiveBatchConn) ReadBatch(m []udptransport.Message) (int, error) {
	c.reads++
	if c.reads > 1 {
		return 0, io.EOF
	}
	for i, p := range c.packets {
		copy(m[i].Payload, p.Payload)
		m[i].N = len(p.Payload)
		m[i].Peer = p.Peer
		m[i].Truncated = p.Truncated
	}
	return len(c.packets), nil
}
func (c *receiveBatchConn) ReadFrom([]byte) (int, net.Addr, error) { panic("single receive used") }
func (c *receiveBatchConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.events != nil {
		p, err := l2tp.DecodePacketView(b)
		if err != nil {
			return 0, err
		}
		if p.Control {
			*c.events = append(*c.events, "control")
		} else {
			*c.events = append(*c.events, "data")
		}
	}
	return len(b), nil
}
func (c *receiveBatchConn) Close() error                     { return nil }
func (c *receiveBatchConn) LocalAddr() net.Addr              { return testPeer("local") }
func (c *receiveBatchConn) SetDeadline(time.Time) error      { return nil }
func (c *receiveBatchConn) SetReadDeadline(time.Time) error  { return nil }
func (c *receiveBatchConn) SetWriteDeadline(time.Time) error { return nil }
func dataSession(t *testing.T) (*Engine, *l2tp.ControlChannel, testPeer, uint16) {
	t.Helper()
	e, ch, peer, now := establishTunnel(t)
	wire, _ := ch.Queue(l2tp.ControlMessage{Type: l2tp.ICRQ, AVPs: []l2tp.AVP{l2tp.Uint16AVP(l2tp.AttrAssignedSessionID, 70, true), l2tp.Uint32AVP(l2tp.AttrCallSerialNumber, 1, true)}}, now)
	r, err := e.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	msg := receiveOne(t, ch, r)
	assigned, _ := msg.Find(l2tp.AttrAssignedSessionID)
	sid, _ := assigned.Uint16()
	wire, _ = ch.Queue(l2tp.ControlMessage{Type: l2tp.ICCN, SessionID: sid}, now)
	r, err = e.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	receiveAck(t, ch, r)
	p, err := ppp.NewSession(ppp.SessionConfig{ServerAddress: netip.MustParseAddr("10.0.0.1"), ClientAddress: netip.MustParseAddr("10.0.0.2"), Authenticate: ppp.StaticCredentials("test", "test")})
	if err != nil {
		t.Fatal(err)
	}
	p.Phase = ppp.PhaseOpen
	session := newSessionRuntime(netip.MustParseAddr("10.0.0.2"))
	session.ppp, session.opened = p, true
	session.sendable.Store(true) // as the Engine does when PPP reaches Open
	e.tunnels[ch.PeerTunnelID].sessions[sid] = session
	return e, ch, peer, sid
}
func dataWire(t *testing.T, tid, sid uint16, value byte) []byte {
	t.Helper()
	ip := []byte{0x45, 0, 0, 21, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, value}
	frame, _ := (ppp.Frame{Protocol: ppp.ProtocolIPv4, Payload: ip}).MarshalBinary()
	wire, err := (l2tp.Packet{TunnelID: tid, SessionID: sid, Payload: frame}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func TestBatchBorrowedLifetimeControlDataAndLegacyCopies(t *testing.T) {
	for _, borrowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "borrowed"}[borrowed], func(t *testing.T) {
			e, ch, peer, sid := dataSession(t)
			events := []string{}
			hello, _ := ch.Queue(l2tp.ControlMessage{Type: l2tp.Hello}, time.Now())
			c := &receiveBatchConn{events: &events, packets: []udptransport.Message{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}, {Payload: hello, Peer: peer}, {Payload: dataWire(t, ch.PeerTunnelID, sid, 2), Peer: peer}}}
			buffers := newTestBuffers()
			s := buffers.install(&Server{Conn: c, Engine: e, BorrowedReceive: borrowed})
			var views [][]byte
			handled := 0
			s.HandleData = func(_ context.Context, f DataFrame) error {
				handled++
				if f.IPv4[20] != byte(handled) {
					t.Fatal("overwritten or reordered borrowed data")
				}
				views = append(views, f.IPv4)
				return nil
			}
			s.RouteIPv4 = func(_ context.Context, f DataFrame, send PacketWriter) error {
				if f.IPv4[20] != byte(handled) {
					t.Fatal("reused before final synchronous consumer")
				}
				events = append(events, "route")
				return send(f.IPv4)
			}
			if err := s.Serve(context.Background()); err != io.EOF {
				t.Fatal(err)
			}
			if handled != 2 || len(events) != 5 || events[0] != "route" || events[1] != "data" || events[2] != "control" || events[3] != "route" || events[4] != "data" {
				t.Fatal(events)
			}
			for i, v := range views {
				if borrowed {
					if !bytes.Equal(v, make([]byte, len(v))) {
						t.Fatal("borrowed storage retained on exit")
					}
				} else if v[20] != byte(i+1) {
					t.Fatal("legacy ownership changed")
				}
			}
			buffers.check(t)
		})
	}
}
func TestTruncatedAndFailedConsumerReleaseReceiveBatch(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	wire := dataWire(t, ch.PeerTunnelID, sid, 1)
	c := &receiveBatchConn{packets: []udptransport.Message{{Payload: wire, Peer: peer, Truncated: true}, {Payload: wire, Peer: peer}}}
	buffers := newTestBuffers()
	s := buffers.install(&Server{Conn: c, Engine: e, BorrowedReceive: true})
	calls := 0
	s.HandleData = func(context.Context, DataFrame) error { calls++; return io.ErrClosedPipe }
	if err := s.Serve(context.Background()); err != io.ErrClosedPipe {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("truncated packet processed")
	}
	buffers.check(t)
}

type queuedOwnedConn struct {
	receiveBatchConn
	pending []struct {
		buffer   *packetbuf.Buffer
		eligible func() bool
	}
}

func (c *queuedOwnedConn) WritePacket(b *packetbuf.Buffer, _ net.Addr, eligible func() bool) error {
	c.pending = append(c.pending, struct {
		buffer   *packetbuf.Buffer
		eligible func() bool
	}{b, eligible})
	return nil
}
func TestOwnedWriterConcurrentClosureAndSessionIdentity(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &queuedOwnedConn{}
	s := &Server{Conn: c, Engine: e}
	write := s.OwnedWriter(ch.PeerTunnelID, sid)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			b := ownedPacket(t, make([]byte, 20))
			err := write(b)
			if err != nil && !errors.Is(err, ErrSessionNotEstablished) && !errors.Is(err, ErrUnknownTunnel) {
				t.Error(err)
			}
		}
	}()
	go func() { defer wg.Done(); e.ClosePeer(peer) }()
	wg.Wait()
	for _, q := range c.pending {
		if q.eligible() {
			t.Fatal("queued packet eligible after closure")
		}
		q.buffer.Release()
	}
	b := ownedPacket(t, make([]byte, 20))
	if err := write(b); !errors.Is(err, ErrSessionNotEstablished) || !isReleased(b) {
		t.Fatalf("stale writer err=%v, buffer not consumed", err)
	}
	replacement, _, _, _ := dataSession(t)
	e.mu.Lock()
	e.tunnels[ch.PeerTunnelID] = replacement.tunnels[ch.PeerTunnelID]
	e.mu.Unlock()
	b = ownedPacket(t, make([]byte, 20))
	if err := write(b); !errors.Is(err, ErrSessionNotEstablished) || !isReleased(b) {
		t.Fatal("old writer reused replacement IDs", err)
	}
}

func TestReceiveDataDoesNotWaitForOutboundSubmission(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &receiveBatchConn{}
	s := &Server{Conn: c, Engine: e, BorrowedReceive: true}
	done := make(chan error, 1)
	s.sendMu.Lock()
	go func() {
		done <- s.processDatagram(context.Background(), peer, dataWire(t, ch.PeerTunnelID, sid, 1), nil, nil)
	}()
	select {
	case err := <-done:
		s.sendMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		s.sendMu.Unlock()
		t.Fatal("receive data blocked by outbound submission")
	}
}

type sizedReceiveBatchConn struct {
	receiveBatchConn
	size int
}

func (c *sizedReceiveBatchConn) BatchSize() int { return c.size }

func TestConfiguredReceiveBatchBoundsAndOwnership(t *testing.T) {
	for _, size := range []int{1, 32, 128, 256} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			e, ch, peer, sid := dataSession(t)
			c := &sizedReceiveBatchConn{size: size}
			for i := 0; i < size; i++ {
				c.packets = append(c.packets, udptransport.Message{Payload: dataWire(t, ch.PeerTunnelID, sid, byte(i)), Peer: peer})
			}
			buffers := newTestBuffers()
			s := buffers.install(&Server{Conn: c, Engine: e, BorrowedReceive: true})
			handled := 0
			s.HandleData = func(_ context.Context, f DataFrame) error {
				if f.IPv4[20] != byte(handled) {
					t.Fatal("configured batch reordered data")
				}
				handled++
				return nil
			}
			if err := s.Serve(context.Background()); err != io.EOF {
				t.Fatal(err)
			}
			// One envelope's buffers serve every read; none are acquired per read.
			if handled != size || buffers.count() != size {
				t.Fatalf("handled=%d buffers=%d want=%d", handled, buffers.count(), size)
			}
			buffers.check(t)
		})
	}
	for _, size := range []int{-1, 0, 257} {
		e, _, _, _ := dataSession(t)
		c := &sizedReceiveBatchConn{size: size}
		buffers := newTestBuffers()
		s := buffers.install(&Server{Conn: c, Engine: e})
		if err := s.Serve(context.Background()); err == nil || buffers.count() != 0 {
			t.Fatalf("invalid size %d: %v", size, err)
		}
	}
}

func TestOwnedRouteFlushBeforeReadReuse(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &receiveBatchConn{packets: []udptransport.Message{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}, {Payload: dataWire(t, ch.PeerTunnelID, sid, 2), Peer: peer}}}
	s := &Server{Conn: c, Engine: e, BorrowedReceive: true}
	var pending [][]byte
	flushed := 0
	s.NewRouteBatch = func(ctx context.Context) (context.Context, func() error) {
		return ctx, func() error {
			if len(pending) == 0 {
				return nil
			}
			if c.reads != 1 {
				t.Fatal("flush waited for next read")
			}
			for i, p := range pending {
				if p[20] != byte(i+1) {
					t.Fatal("packet cleared before flush")
				}
			}
			flushed++
			pending = nil
			return nil
		}
	}
	s.RouteIPv4Owned = func(_ context.Context, f DataFrame, _ PacketWriter) error {
		if f.Buffer.Headroom() < 16 || &f.Buffer.Bytes()[0] != &f.IPv4[0] || f.Buffer.Len() != len(f.IPv4) {
			t.Fatal("missing headroom, wrong view or copied packet")
		}
		pending = append(pending, f.IPv4)
		return nil
	}
	if err := s.Serve(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	if flushed != 1 {
		t.Fatalf("flushes=%d", flushed)
	}
}

// The receive buffer's own headroom precedes every owned frame; a router may
// write into it, and recycling clears it and restores the receive view.
func TestOwnedFrameViewHeadroomAndRecycle(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &reuseReceiveConn{receiveBatchConn: receiveBatchConn{packets: []udptransport.Message{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}}}}
	buffers := newTestBuffers()
	c.buffers = buffers
	s := buffers.install(&Server{Conn: c, Engine: e, BorrowedReceive: true, NewRouteBatch: func(ctx context.Context) (context.Context, func() error) {
		return ctx, func() error { return nil }
	}})
	routed := 0
	s.RouteIPv4Owned = func(_ context.Context, f DataFrame, _ PacketWriter) error {
		routed++
		// A router prepends its header in the headroom and leaves the view moved.
		header, err := f.Buffer.Prepend(16)
		if err != nil {
			t.Fatal(err)
		}
		for i := range header {
			header[i] = 0xee
		}
		if f.IPv4[0] != 0x45 || f.IPv4[20] != 1 {
			t.Fatal("frame view is not the IPv4 packet")
		}
		return nil
	}
	if err := s.Serve(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	if routed != 1 {
		t.Fatalf("routed=%d", routed)
	}
	buffers.check(t)
}

// Legacy consumers keep independent copies when an owned router is set but
// the owned path cannot be used for a frame.
func TestOwnedRouterFallbackKeepsLegacyCopies(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	wire := dataWire(t, ch.PeerTunnelID, sid, 1)
	s := &Server{Conn: &receiveBatchConn{}, Engine: e}
	s.RouteIPv4Owned = func(context.Context, DataFrame, PacketWriter) error {
		t.Fatal("owned path used without packet storage")
		return nil
	}
	var routed, handled []byte
	s.RouteIPv4 = func(_ context.Context, f DataFrame, _ PacketWriter) error { routed = f.IPv4; return nil }
	s.HandleData = func(_ context.Context, f DataFrame) error { handled = f.PPP.Payload; return nil }
	if err := s.processDatagram(context.Background(), peer, wire, nil, nil); err != nil {
		t.Fatal(err)
	}
	if routed == nil || handled == nil {
		t.Fatal("legacy callbacks not called")
	}
	clear(wire)
	if routed[20] != 1 || handled[len(handled)-1] != 1 {
		t.Fatal("legacy callbacks received borrowed views")
	}
}

func TestReceiveAllocationFailureReleasesPartialBatch(t *testing.T) {
	for _, small := range []bool{false, true} {
		buffers := newTestBuffers()
		buffers.failAt, buffers.small = 3, small
		s := buffers.install(&Server{Conn: &receiveBatchConn{}, Engine: NewEngine(Config{})})
		if err := s.Serve(context.Background()); err == nil {
			t.Fatal("expected allocation failure")
		}
		buffers.check(t)
	}
}

type reuseReceiveConn struct {
	receiveBatchConn
	buffers *testBuffers
}

// At the second read, the first read's buffers must already be flushed and
// cleared, back at their receive view, but still owned (reused, not released).
func (c *reuseReceiveConn) ReadBatch(m []udptransport.Message) (int, error) {
	if c.reads == 1 {
		if c.buffers.count() != c.BatchSize() {
			return 0, errors.New("receive buffers acquired per read")
		}
		for i, b := range c.buffers.all {
			if c.buffers.released(b) != 0 {
				return 0, errors.New("receive storage released before Serve ends")
			}
			if b.Headroom() != packetbuf.Headroom || b.Len() != packetbuf.MaxPacket || &b.Bytes()[0] != &m[i].Payload[0] {
				return 0, errors.New("receive view not restored")
			}
			_, _ = b.Prepend(b.Headroom())
			for _, v := range b.Bytes() {
				if v != 0 {
					return 0, errors.New("received bytes or headroom not cleared before reuse")
				}
			}
			_ = b.TrimFront(packetbuf.Headroom)
		}
	}
	return c.receiveBatchConn.ReadBatch(m)
}
func TestSynchronousReceiveReusesClearedBuffersAfterFlush(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &reuseReceiveConn{receiveBatchConn: receiveBatchConn{packets: []udptransport.Message{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}}}}
	buffers := newTestBuffers()
	c.buffers = buffers
	s := buffers.install(&Server{Conn: c, Engine: e})
	if err := s.Serve(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	buffers.check(t)
}

type flowOwnedConn struct {
	receiveBatchConn
	flows    []uint32
	payloads [][]byte
	eligible []func() bool
}

func (c *flowOwnedConn) WriteFlowPacket(b *packetbuf.Buffer, _ net.Addr, eligible func() bool, flow uint32) error {
	c.flows = append(c.flows, flow)
	c.payloads = append(c.payloads, append([]byte(nil), b.Bytes()...))
	c.eligible = append(c.eligible, eligible)
	b.Release()
	return nil
}

func TestOwnedFlowWriterMatchesOwnedWriterFraming(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	flowConn := &flowOwnedConn{}
	write := (&Server{Conn: flowConn, Engine: e}).OwnedFlowWriter(ch.PeerTunnelID, sid)
	queued := &queuedOwnedConn{}
	legacy := (&Server{Conn: queued, Engine: e}).OwnedWriter(ch.PeerTunnelID, sid)
	ip := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	b := ownedPacket(t, ip)
	if err := write(b, 0xabcd); err != nil {
		t.Fatal(err)
	}
	b = ownedPacket(t, ip)
	if err := legacy(b); err != nil {
		t.Fatal(err)
	}
	if len(flowConn.flows) != 1 || flowConn.flows[0] != 0xabcd {
		t.Fatalf("flow key not passed: %v", flowConn.flows)
	}
	if string(flowConn.payloads[0]) != string(queued.pending[0].buffer.Bytes()) {
		t.Fatal("flow writer framing differs from OwnedWriter")
	}
	queued.pending[0].buffer.Release()
	if !flowConn.eligible[0]() {
		t.Fatal("open session ineligible")
	}
	e.ClosePeer(peer)
	if flowConn.eligible[0]() {
		t.Fatal("closed session still eligible")
	}
	b = ownedPacket(t, make([]byte, 20))
	if err := write(b, 1); !errors.Is(err, ErrSessionNotEstablished) || !isReleased(b) {
		t.Fatalf("closed session err=%v, buffer not consumed", err)
	}
	// A writer for a session that is already gone rejects and consumes.
	b = ownedPacket(t, make([]byte, 20))
	if err := (&Server{Conn: flowConn, Engine: e}).OwnedFlowWriter(ch.PeerTunnelID, sid)(b, 1); err == nil || !isReleased(b) {
		t.Fatalf("stale writer err=%v, buffer not consumed", err)
	}
}

func TestOwnedFlowWriterConcurrentClosure(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &queuedOwnedConn{}
	write := (&Server{Conn: c, Engine: e}).OwnedFlowWriter(ch.PeerTunnelID, sid)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			b := ownedPacket(t, make([]byte, 20))
			if err := write(b, uint32(i)); err != nil && !errors.Is(err, ErrSessionNotEstablished) {
				t.Error(err)
			}
		}
	}()
	go func() { defer wg.Done(); e.ClosePeer(peer) }()
	wg.Wait()
	for _, q := range c.pending {
		if q.eligible() {
			t.Fatal("queued packet eligible after closure")
		}
		q.buffer.Release()
	}
}

type releasingFlowConn struct{ receiveBatchConn }

func (releasingFlowConn) WriteFlowPacket(b *packetbuf.Buffer, _ net.Addr, _ func() bool, _ uint32) error {
	b.Release()
	return nil
}

func TestOwnedFlowWriterDoesNotAllocate(t *testing.T) {
	e, ch, _, sid := dataSession(t)
	write := (&Server{Conn: &releasingFlowConn{}, Engine: e}).OwnedFlowWriter(ch.PeerTunnelID, sid)
	allocs := testing.AllocsPerRun(1000, func() {
		b, err := packetbuf.Acquire(20)
		if err != nil {
			t.Fatal(err)
		}
		if err := write(b, 7); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("OwnedFlowWriter allocated %.1f times per packet", allocs)
	}
}

// An embedder's driver-owned buffer (as ESP delivery hands over) routes the
// frame in place: the view becomes exactly the IPv4 packet, with every byte in
// front of it as headroom. A frame outside its buffer takes the RouteIPv4 path.
func TestDispatchIPv4RoutesDriverBufferInPlace(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	buffer := ownedPacket(t, append(make([]byte, 30), dataWire(t, ch.PeerTunnelID, sid, 7)[8:]...))
	defer buffer.Release()
	if err := buffer.TrimFront(10); err != nil { // a consumed outer header
		t.Fatal(err)
	}
	view := buffer.Bytes()
	ipv4 := view[20+4:] // after 20 bytes of other headers and the PPP header
	s := &Server{Conn: &receiveBatchConn{}, Engine: e}
	var owned, copied int
	s.RouteIPv4Owned = func(_ context.Context, f DataFrame, _ PacketWriter) error {
		owned++
		if &f.IPv4[0] != &ipv4[0] || &f.Buffer.Bytes()[0] != &ipv4[0] || f.Buffer.Len() != len(ipv4) || f.Buffer.Headroom() != packetbuf.Headroom+34 {
			t.Fatalf("view len=%d headroom=%d", f.Buffer.Len(), f.Buffer.Headroom())
		}
		return nil
	}
	s.RouteIPv4 = func(_ context.Context, f DataFrame, _ PacketWriter) error {
		copied++
		return nil
	}
	write := func(net.Addr, uint16, uint16, []byte) error { return nil }
	frame := &DataFrame{TunnelID: ch.PeerTunnelID, Session: l2tp.Session{LocalID: sid}, IPv4: ipv4, Peer: peer, Buffer: buffer}
	if err := s.DispatchIPv4(context.Background(), Result{Data: frame}, "l2tp/ipsec", write); err != nil {
		t.Fatal(err)
	}
	outside := *frame
	outside.IPv4 = append([]byte(nil), ipv4...)
	if err := s.DispatchIPv4(context.Background(), Result{Data: &outside}, "l2tp/ipsec", write); err != nil {
		t.Fatal(err)
	}
	if owned != 1 || copied != 1 {
		t.Fatalf("owned=%d copied=%d", owned, copied)
	}
}

// An embedder's IPv4 dispatch reuses one writer per session, and a session's
// eligibility check is a bound value: neither allocates per packet.
func TestDispatchIPv4SteadyStateDoesNotAllocate(t *testing.T) {
	e, ch, _, sid := dataSession(t)
	// A socket peer, as the ESP bridge passes: comparing it allocates nothing.
	var peer net.Addr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 1701}
	e.tunnels[ch.PeerTunnelID].peer = peer
	buffer := ownedPacket(t, dataWire(t, ch.PeerTunnelID, sid, 7)[8:])
	defer buffer.Release()
	ipv4 := buffer.Bytes()[4:]
	s := &Server{Conn: &receiveBatchConn{}, Engine: e}
	routed := 0
	s.RouteIPv4Owned = func(context.Context, DataFrame, PacketWriter) error { routed++; return nil }
	write := func(net.Addr, uint16, uint16, []byte) error { return nil }
	frame := &DataFrame{TunnelID: ch.PeerTunnelID, Session: l2tp.Session{LocalID: sid}, IPv4: ipv4, Peer: peer, Buffer: buffer}
	ctx := context.Background()
	// Routing trims the buffer to the IPv4 view, which later packets reuse.
	dispatch := func() {
		if err := s.DispatchIPv4(ctx, Result{Data: frame}, "l2tp/ipsec", write); err != nil {
			t.Fatal(err)
		}
		frame.IPv4 = buffer.Bytes()
	}
	dispatch()
	if allocs := testing.AllocsPerRun(100, dispatch); allocs != 0 {
		t.Fatalf("IPv4 dispatch allocates %v per packet", allocs)
	}
	if routed != 102 || len(s.writers) != 1 {
		t.Fatalf("routed=%d writers=%d", routed, len(s.writers))
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = e.SessionEligibility(ch.PeerTunnelID, sid) }); allocs != 0 {
		t.Fatalf("session eligibility allocates %v", allocs)
	}
}

// A plain data packet costs no allocation from receive through dispatch to
// the owned router when tracing is off and the caller supplies frame storage.
func TestPlainDataPathDoesNotAllocate(t *testing.T) {
	e, ch, _, sid := dataSession(t)
	// A socket peer, as received: address conversion and comparison allocate nothing.
	var peer net.Addr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 1701}
	e.tunnels[ch.PeerTunnelID].peer = peer
	s := &Server{Conn: &receiveBatchConn{}, Engine: e, BorrowedReceive: true}
	s.plainWrite = s.writeConn
	wire := dataWire(t, ch.PeerTunnelID, sid, 1)
	buffer := ownedPacket(t, wire)
	defer buffer.Release()
	routed := 0
	s.RouteIPv4Owned = func(context.Context, DataFrame, PacketWriter) error { routed++; return nil }
	var frame DataFrame
	ctx := context.Background()
	process := func() {
		_, _ = buffer.Prepend(buffer.Headroom())
		_ = buffer.TrimFront(packetbuf.Headroom)
		if err := s.processDatagram(ctx, peer, buffer.Bytes(), buffer, &frame); err != nil {
			t.Fatal(err)
		}
	}
	process()
	if allocs := testing.AllocsPerRun(200, process); allocs != 0 {
		t.Fatalf("plain data packet allocates %v times", allocs)
	}
	if routed != 202 {
		t.Fatalf("routed=%d", routed)
	}
}

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
)

type receiveOwner struct {
	data     []byte
	released int
}

func (b *receiveOwner) Bytes() []byte { return b.data }
func (b *receiveOwner) Release() {
	b.released++
	if b.released != 1 {
		panic("double release")
	}
	clear(b.data)
}

type receiveBatchConn struct {
	packets []ReceivedDatagram
	reads   int
	owners  []*receiveOwner
	events  *[]string
}

func (c *receiveBatchConn) BatchSize() int { return 8 }
func (c *receiveBatchConn) AcquireReceiveBuffer() (ReceiveBuffer, error) {
	b := &receiveOwner{data: make([]byte, 2048)}
	c.owners = append(c.owners, b)
	return b, nil
}
func (c *receiveBatchConn) ReadBatch(m []ReceivedDatagram) (int, error) {
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
	e.tunnels[ch.PeerTunnelID].sessions[sid] = &sessionRuntime{ppp: p, opened: true, address: netip.MustParseAddr("10.0.0.2")}
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
			c := &receiveBatchConn{events: &events, packets: []ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}, {Payload: hello, Peer: peer}, {Payload: dataWire(t, ch.PeerTunnelID, sid, 2), Peer: peer}}}
			s := &Server{Conn: c, Engine: e, BorrowedReceive: borrowed}
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
			for _, b := range c.owners {
				if b.released != 1 {
					t.Fatal("receive ownership leak")
				}
			}
		})
	}
}
func TestTruncatedAndFailedConsumerReleaseReceiveBatch(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	wire := dataWire(t, ch.PeerTunnelID, sid, 1)
	c := &receiveBatchConn{packets: []ReceivedDatagram{{Payload: wire, Peer: peer, Truncated: true}, {Payload: wire, Peer: peer}}}
	s := &Server{Conn: c, Engine: e, BorrowedReceive: true}
	calls := 0
	s.HandleData = func(context.Context, DataFrame) error { calls++; return io.ErrClosedPipe }
	if err := s.Serve(context.Background()); err != io.ErrClosedPipe {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("truncated packet processed")
	}
	for _, b := range c.owners {
		if b.released != 1 || !bytes.Equal(b.data, make([]byte, len(b.data))) {
			t.Fatal("batch storage leak on dispatch error")
		}
	}
}

type ownedTestBuffer struct {
	storage  []byte
	start    int
	released int
}

func (b *ownedTestBuffer) Len() int      { return len(b.storage) - b.start }
func (b *ownedTestBuffer) Bytes() []byte { return b.storage[b.start:] }
func (b *ownedTestBuffer) Prepend(n int) ([]byte, error) {
	if n > b.start {
		return nil, io.ErrShortBuffer
	}
	b.start -= n
	return b.storage[b.start : b.start+n], nil
}
func (b *ownedTestBuffer) Release() {
	b.released++
	if b.released != 1 {
		panic("double release")
	}
	clear(b.storage)
}

type queuedOwnedConn struct {
	receiveBatchConn
	pending []struct {
		buffer   OwnedPacketBuffer
		eligible func() bool
	}
}

func (c *queuedOwnedConn) WritePacket(b OwnedPacketBuffer, _ net.Addr, eligible func() bool) error {
	c.pending = append(c.pending, struct {
		buffer   OwnedPacketBuffer
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
			b := &ownedTestBuffer{storage: make([]byte, 64+20), start: 64}
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
	b := &ownedTestBuffer{storage: make([]byte, 84), start: 64}
	if err := write(b); !errors.Is(err, ErrSessionNotEstablished) || b.released != 1 {
		t.Fatalf("stale writer err=%v releases=%d", err, b.released)
	}
	replacement, _, _, _ := dataSession(t)
	e.mu.Lock()
	e.tunnels[ch.PeerTunnelID] = replacement.tunnels[ch.PeerTunnelID]
	e.mu.Unlock()
	b = &ownedTestBuffer{storage: make([]byte, 84), start: 64}
	if err := write(b); !errors.Is(err, ErrSessionNotEstablished) {
		t.Fatal("old writer reused replacement IDs", err)
	}
}

func TestReceiveDataDoesNotWaitForOutboundSubmission(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &receiveBatchConn{}
	s := &Server{Conn: c, Engine: e, BorrowedReceive: true}
	done := make(chan error, 1)
	s.sendMu.Lock()
	go func() { done <- s.processDatagram(context.Background(), peer, dataWire(t, ch.PeerTunnelID, sid, 1)) }()
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
				c.packets = append(c.packets, ReceivedDatagram{Payload: dataWire(t, ch.PeerTunnelID, sid, byte(i)), Peer: peer})
			}
			s := &Server{Conn: c, Engine: e, BorrowedReceive: true}
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
			if handled != size || len(c.owners) != 2*size {
				t.Fatalf("handled=%d owners=%d want=%d", handled, len(c.owners), size)
			}
			for _, b := range c.owners {
				if b.released != 1 {
					t.Fatal("configured batch leaked ownership")
				}
			}
		})
	}
	for _, size := range []int{-1, 0, 257} {
		e, _, _, _ := dataSession(t)
		c := &sizedReceiveBatchConn{size: size}
		s := &Server{Conn: c, Engine: e}
		if err := s.Serve(context.Background()); err == nil || len(c.owners) != 0 {
			t.Fatalf("invalid size %d: %v", size, err)
		}
	}
}

func TestOwnedRouteFlushBeforeReadReuse(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &receiveBatchConn{packets: []ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}, {Payload: dataWire(t, ch.PeerTunnelID, sid, 2), Peer: peer}}}
	s := &Server{Conn: c, Engine: e, BorrowedReceive: true, ReceiveHeadroom: 16}
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
	s.RouteIPv4Owned = func(_ context.Context, f DataFrame, storage []byte, offset int, _ PacketWriter) error {
		if offset < 16 || &storage[offset] != &f.IPv4[0] {
			t.Fatal("missing headroom or copied packet")
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

func TestReceiveHeadroomDefaultsToZeroAndIsBounded(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &receiveBatchConn{packets: []ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}}}
	s := &Server{Conn: c, Engine: e, BorrowedReceive: true, NewRouteBatch: func(ctx context.Context) (context.Context, func() error) {
		return ctx, func() error { return nil }
	}}
	var offset int
	s.RouteIPv4Owned = func(_ context.Context, f DataFrame, storage []byte, o int, _ PacketWriter) error {
		offset = o
		return nil
	}
	if err := s.Serve(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	// With no headroom, the frame starts right after the L2TP and PPP headers.
	if offset <= 0 || offset >= 16 {
		t.Fatalf("offset=%d with default headroom", offset)
	}
	for _, bad := range []int{-1, 65} {
		s := &Server{Conn: &receiveBatchConn{}, Engine: e, ReceiveHeadroom: bad}
		if err := s.Serve(context.Background()); err == nil || err == io.EOF {
			t.Fatalf("headroom %d accepted", bad)
		}
	}
}

// Legacy consumers keep independent copies when an owned router is set but
// the owned path cannot be used for a frame.
func TestOwnedRouterFallbackKeepsLegacyCopies(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	wire := dataWire(t, ch.PeerTunnelID, sid, 1)
	s := &Server{Conn: &receiveBatchConn{}, Engine: e}
	s.RouteIPv4Owned = func(context.Context, DataFrame, []byte, int, PacketWriter) error {
		t.Fatal("owned path used without packet storage")
		return nil
	}
	var routed, handled []byte
	s.RouteIPv4 = func(_ context.Context, f DataFrame, _ PacketWriter) error { routed = f.IPv4; return nil }
	s.HandleData = func(_ context.Context, f DataFrame) error { handled = f.PPP.Payload; return nil }
	if err := s.processDatagram(context.Background(), peer, wire); err != nil {
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

type failingReceiveAllocator struct {
	receiveBatchConn
	failAt int
	small  bool
}

func (c *failingReceiveAllocator) AcquireReceiveBuffer() (ReceiveBuffer, error) {
	if len(c.owners) == c.failAt {
		return nil, io.ErrShortBuffer
	}
	b, err := c.receiveBatchConn.AcquireReceiveBuffer()
	if c.small {
		c.owners[len(c.owners)-1].data = make([]byte, 8)
	}
	return b, err
}
func TestReceiveAllocationFailureReleasesPartialBatch(t *testing.T) {
	for _, small := range []bool{false, true} {
		c := &failingReceiveAllocator{failAt: 3, small: small}
		s := &Server{Conn: c, Engine: NewEngine(Config{}), ReceiveHeadroom: 16}
		if err := s.Serve(context.Background()); err == nil {
			t.Fatal("expected allocation failure")
		}
		for _, b := range c.owners {
			if b.released != 1 {
				t.Fatal("partial batch leaked")
			}
		}
	}
}

type freshReceiveConn struct{ receiveBatchConn }

func (c *freshReceiveConn) ReadBatch(m []ReceivedDatagram) (int, error) {
	if c.reads == 1 {
		for i, b := range c.owners {
			want := 0
			if i < c.BatchSize() {
				want = 1
			}
			if b.released != want {
				return 0, errors.New("receive storage reused or released early")
			}
		}
	}
	return c.receiveBatchConn.ReadBatch(m)
}
func TestSynchronousReceiveUsesFreshBuffersAfterFlush(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := &freshReceiveConn{receiveBatchConn{packets: []ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}}}}
	s := &Server{Conn: c, Engine: e}
	if err := s.Serve(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	if len(c.owners) != 2*c.BatchSize() {
		t.Fatal("read slots were reused")
	}
}

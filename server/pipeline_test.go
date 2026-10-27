package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
)

type pipelineOwner struct {
	data     []byte
	releases atomic.Int32
}

func (b *pipelineOwner) Bytes() []byte { return b.data }
func (b *pipelineOwner) Release() {
	if b.releases.Add(1) != 1 {
		panic("double release")
	}
	clear(b.data)
}

type pipelineConn struct {
	mu           sync.Mutex
	batches      [][]ReceivedDatagram
	owners       []*pipelineOwner
	reads        int
	size         int
	failAt       int
	readErr      error
	invalidCount bool
	waitAtEnd    bool
	wake         chan struct{}
	once         sync.Once
	control      func([]byte)
}

func newPipelineConn(packets ...[]ReceivedDatagram) *pipelineConn {
	return &pipelineConn{batches: packets, size: 1, failAt: -1, wake: make(chan struct{}), readErr: io.EOF}
}
func (c *pipelineConn) BatchSize() int { return c.size }
func (c *pipelineConn) AcquireReceiveBuffer() (ReceiveBuffer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAt >= 0 && len(c.owners) == c.failAt {
		return nil, io.ErrShortBuffer
	}
	b := &pipelineOwner{data: make([]byte, 2048)}
	c.owners = append(c.owners, b)
	return b, nil
}
func (c *pipelineConn) ReadBatch(messages []ReceivedDatagram) (int, error) {
	c.mu.Lock()
	i := c.reads
	c.reads++
	c.mu.Unlock()
	if c.invalidCount {
		return len(messages) + 1, nil
	}
	if i >= len(c.batches) {
		if c.waitAtEnd {
			<-c.wake
		}
		return 0, c.readErr
	}
	for j, p := range c.batches[i] {
		copy(messages[j].Payload, p.Payload)
		messages[j].N = len(p.Payload)
		messages[j].Peer = p.Peer
		messages[j].Truncated = p.Truncated
	}
	return len(c.batches[i]), nil
}
func (c *pipelineConn) ReadFrom([]byte) (int, net.Addr, error) { panic("single read") }
func (c *pipelineConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.control != nil {
		c.control(p)
	}
	return len(p), nil
}
func (c *pipelineConn) Close() error        { c.once.Do(func() { close(c.wake) }); return nil }
func (c *pipelineConn) LocalAddr() net.Addr { return testPeer("local") }
func (c *pipelineConn) SetReadDeadline(t time.Time) error {
	if !t.After(time.Now()) {
		return c.Close()
	}
	return nil
}
func (c *pipelineConn) SetWriteDeadline(time.Time) error { return nil }
func (c *pipelineConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *pipelineConn) readCount() int                   { c.mu.Lock(); defer c.mu.Unlock(); return c.reads }
func (c *pipelineConn) checkReleased(t *testing.T) {
	t.Helper()
	for _, b := range c.owners {
		if b.releases.Load() != 1 {
			t.Fatalf("buffer released %d times", b.releases.Load())
		}
	}
}
func awaitPipeline(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline did not finish")
		return nil
	}
}

func TestPipelineOrderedDataControlMultipleTunnels(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	other, och, _, osid := dataSession(t)
	// Install a distinct established tunnel, with its own control sequence.
	tid := ch.PeerTunnelID + 1
	runtime := other.tunnels[och.PeerTunnelID]
	runtime.state.LocalTunnelID = tid
	runtime.peer = testPeer("second-peer")
	e.tunnels[tid] = runtime
	och.PeerTunnelID = tid
	hello, _ := ch.Queue(l2tp.ControlMessage{Type: l2tp.Hello}, time.Now())
	ohello, _ := och.Queue(l2tp.ControlMessage{Type: l2tp.Hello}, time.Now())
	c := newPipelineConn(
		[]ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}},
		[]ReceivedDatagram{{Payload: hello, Peer: peer}},
		[]ReceivedDatagram{{Payload: dataWire(t, tid, osid, 2), Peer: runtime.peer}},
		[]ReceivedDatagram{{Payload: ohello, Peer: runtime.peer}},
		[]ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, 3), Peer: peer}},
	)
	var process []string
	c.control = func(p []byte) {
		packet, err := l2tp.DecodePacketView(p)
		if err != nil {
			t.Error(err)
		}
		if packet.Control {
			process = append(process, "control")
		}
	}
	s := &Server{Conn: c, Engine: e, BorrowedReceive: true, ReceivePipeline: true}
	var flushed []byte
	type batchKey struct{}
	s.NewRouteBatch = func(ctx context.Context) (context.Context, func() error) {
		var views [][]byte
		return context.WithValue(ctx, batchKey{}, &views), func() error {
			for _, v := range views {
				flushed = append(flushed, v[20])
			}
			return nil
		}
	}
	s.RouteIPv4Owned = func(ctx context.Context, f DataFrame, storage []byte, offset int, _ PacketWriter) error {
		if &storage[offset] != &f.IPv4[0] {
			t.Error("packet copied")
		}
		process = append(process, fmt.Sprint(f.IPv4[20]))
		p := ctx.Value(batchKey{}).(*[][]byte)
		*p = append(*p, f.IPv4)
		return nil
	}
	if err := s.Serve(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(process, []string{"1", "control", "2", "control", "3"}) {
		t.Fatal(process)
	}
	if !reflect.DeepEqual(flushed, []byte{1, 2, 3}) {
		t.Fatal(flushed)
	}
	c.checkReleased(t)
}

func TestPipelineBackpressureAndDisabledSynchronousPath(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			e, ch, peer, sid := dataSession(t)
			c := newPipelineConn()
			for i := 0; i < 80; i++ {
				c.batches = append(c.batches, []ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, byte(i)), Peer: peer}})
			}
			s := &Server{Conn: c, Engine: e, BorrowedReceive: true, ReceivePipeline: enabled}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			type batchKey struct{}
			var flushed []byte
			s.NewRouteBatch = func(ctx context.Context) (context.Context, func() error) {
				var pending [][]byte
				return context.WithValue(ctx, batchKey{}, &pending), func() error {
					if len(pending) == 0 {
						return nil
					}
					once.Do(func() { close(entered); <-release })
					for _, p := range pending {
						flushed = append(flushed, p[20])
					}
					pending = nil
					return nil
				}
			}
			s.RouteIPv4Owned = func(ctx context.Context, f DataFrame, _ []byte, _ int, _ PacketWriter) error {
				p := ctx.Value(batchKey{}).(*[][]byte)
				*p = append(*p, f.IPv4)
				return nil
			}
			done := make(chan error, 1)
			go func() { done <- s.Serve(context.Background()) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("no flush")
			}
			if enabled {
				deadline := time.Now().Add(time.Second)
				for c.readCount() < 7 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
			}
			time.Sleep(20 * time.Millisecond)
			n := c.readCount()
			if enabled {
				if n != 7 {
					t.Errorf("bounded pipeline reads=%d want 7", n)
				}
			} else if n != 1 {
				t.Errorf("disabled path read ahead: %d", n)
			}
			close(release)
			if err := awaitPipeline(t, done); err != io.EOF {
				t.Fatal(err)
			}
			if len(flushed) != 80 {
				t.Fatalf("lost packets: %d", len(flushed))
			}
			for i, v := range flushed {
				if v != byte(i) {
					t.Fatal("reordered/overwritten storage")
				}
			}
			c.checkReleased(t)
		})
	}
}

func TestPipelineErrorsAndCancellationReleaseEveryBuffer(t *testing.T) {
	for _, failure := range []string{"receive", "process", "flush", "allocate", "invalid-count", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			e, ch, peer, sid := dataSession(t)
			c := newPipelineConn()
			for i := 0; i < 20; i++ {
				c.batches = append(c.batches, []ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, byte(i)), Peer: peer}})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &Server{Conn: c, Engine: e, ReceivePipeline: true, BorrowedReceive: true}
			sentinel := errors.New("injected failure")
			c.readErr = sentinel
			if failure == "allocate" {
				c.failAt = 3
			}
			if failure == "invalid-count" {
				c.invalidCount = true
			}
			if failure == "cancel" {
				c.waitAtEnd = true
			}
			s.HandleData = func(context.Context, DataFrame) error {
				if failure == "process" {
					return sentinel
				}
				return nil
			}
			s.NewRouteBatch = func(ctx context.Context) (context.Context, func() error) {
				return ctx, func() error {
					if failure == "flush" {
						return sentinel
					}
					if failure == "cancel" {
						cancel()
					}
					return nil
				}
			}
			done := make(chan error, 1)
			go func() { done <- s.Serve(ctx) }()
			err := awaitPipeline(t, done)
			switch failure {
			case "cancel":
				if err != nil {
					t.Fatal(err)
				}
			case "allocate":
				if !errors.Is(err, io.ErrShortBuffer) {
					t.Fatal(err)
				}
			case "invalid-count":
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, sentinel) {
					t.Fatal(err)
				}
			}
			c.checkReleased(t)
		})
	}
}

func TestPipelineFlushesWithoutWaitingForMoreTraffic(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	c := newPipelineConn([]ReceivedDatagram{{Payload: dataWire(t, ch.PeerTunnelID, sid, 1), Peer: peer}})
	c.waitAtEnd = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{Conn: c, Engine: e, ReceivePipeline: true}
	flushed := make(chan struct{}, 1)
	s.NewRouteBatch = func(ctx context.Context) (context.Context, func() error) {
		return ctx, func() error { flushed <- struct{}{}; return nil }
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Error("packet waited for next read")
	}
	cancel()
	if err := awaitPipeline(t, done); err != nil {
		t.Fatal(err)
	}
	c.checkReleased(t)
}

func TestSessionBindingGuardRejectsClosedOrReplacedIdentity(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	guard := e.SessionBindingGuard(ch.PeerTunnelID, sid)
	bound := false
	if !guard(func() { bound = true }) || !bound {
		t.Fatal("active guard rejected")
	}
	e.ClosePeer(peer)
	if guard(func() { t.Error("published after closure") }) {
		t.Fatal("closed guard accepted")
	}
	replacement, _, _, _ := dataSession(t)
	e.mu.Lock()
	e.tunnels[ch.PeerTunnelID] = replacement.tunnels[ch.PeerTunnelID]
	e.mu.Unlock()
	if guard(func() { t.Error("published through reused IDs") }) {
		t.Fatal("stale guard accepted")
	}
}

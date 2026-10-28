package server

import (
	"io"
	"sync"
	"testing"

	"github.com/eukhlg/netio/packetbuf"
)

// testBuffers counts the receive buffers a Server acquires and releases
// through its storage seam; failAt >= 0 fails that acquisition.
type testBuffers struct {
	mu       sync.Mutex
	failAt   int
	small    bool // hand out buffers without headroom
	all      []*packetbuf.Buffer
	releases map[*packetbuf.Buffer]int
}

func newTestBuffers() *testBuffers {
	return &testBuffers{failAt: -1, releases: map[*packetbuf.Buffer]int{}}
}

func (p *testBuffers) install(s *Server) *Server {
	s.acquire, s.release = p.acquire, p.releaseBuffer
	return s
}

func (p *testBuffers) acquire(n int) (*packetbuf.Buffer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failAt >= 0 && len(p.all) == p.failAt {
		return nil, io.ErrShortBuffer
	}
	b, err := packetbuf.Acquire(n)
	if err != nil {
		return nil, err
	}
	if p.small {
		_, _ = b.Prepend(b.Headroom())
	}
	p.all = append(p.all, b)
	return b, nil
}

func (p *testBuffers) releaseBuffer(b *packetbuf.Buffer) {
	p.mu.Lock()
	p.releases[b]++
	p.mu.Unlock()
	b.Release() // panics on a double release
}

func (p *testBuffers) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.all) }

func (p *testBuffers) released(b *packetbuf.Buffer) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.releases[b]
}

// check requires every acquired buffer to be released exactly once.
func (p *testBuffers) check(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.all {
		if p.releases[b] != 1 {
			t.Fatalf("receive buffer released %d times", p.releases[b])
		}
	}
}

// ownedPacket returns a pooled buffer holding payload behind the pool's headroom.
func ownedPacket(t *testing.T, payload []byte) *packetbuf.Buffer {
	t.Helper()
	b, err := packetbuf.Copy(payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// isReleased reports whether b was already released; it releases b if not.
func isReleased(b *packetbuf.Buffer) (released bool) {
	defer func() { released = recover() != nil }()
	b.Release()
	return false
}

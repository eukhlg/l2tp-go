package server

import (
	"net"
	"testing"
)

func TestSamePeerMatchesKeys(t *testing.T) {
	peers := []net.Addr{nil, (*net.UDPAddr)(nil), &net.UDPAddr{}, &net.UDPAddr{IP: net.IP{}},
		&net.UDPAddr{IP: net.IP{1, 2}}, &net.UDPAddr{IP: net.IP{1, 3}},
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1701},
		&net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 1701},
		&net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 1702},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 1701, Zone: "en0"},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 1701, Zone: "en1"}, testPeer("peer"), testPeer("other")}
	for _, a := range peers {
		for _, b := range peers {
			if got, want := samePeer(a, b), peerKey(a) == peerKey(b); got != want {
				t.Fatalf("%#v vs %#v: got %v want %v", a, b, got, want)
			}
		}
	}
}

var peerComparison bool

func BenchmarkSamePeerUDP(b *testing.B) {
	a := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1701}
	c := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 1701}
	b.ReportAllocs()
	for b.Loop() {
		peerComparison = samePeer(a, c)
	}
}

func TestPlainWriterCachedPerSessionAndForgotten(t *testing.T) {
	e, _, _, sid := dataSession(t)
	s := &Server{Conn: &receiveBatchConn{}, Engine: e}
	var tid uint16
	for id := range e.tunnels {
		tid = id
	}
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1701}
	_ = s.plainWriter(peer, tid, sid)
	// A rebuilt writer allocates; a cached lookup must not.
	if allocs := testing.AllocsPerRun(100, func() { _ = s.plainWriter(peer, tid, sid) }); allocs != 0 {
		t.Fatalf("cached writer lookup allocates %v", allocs)
	}
	if len(s.writers) != 1 {
		t.Fatalf("writers=%d", len(s.writers))
	}
	s.forgetWriter(tid, sid)
	if len(s.writers) != 0 {
		t.Fatal("writer not forgotten")
	}
	other := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 1701}
	alternate := func() { _ = s.plainWriter(other, tid, sid); _ = s.plainWriter(peer, tid, sid) }
	if allocs := testing.AllocsPerRun(10, alternate); allocs == 0 {
		t.Fatal("writer reused for a different peer")
	}
}

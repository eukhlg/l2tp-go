package server

import (
	"errors"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
)

func TestNewTunnelLimiterBurstRefillAndSourceIsolation(t *testing.T) {
	limiter := newNewTunnelLimiter(1, 2)
	now := time.Unix(100, 0)
	if !limiter.allow("192.0.2.1", now) || !limiter.allow("192.0.2.1", now) {
		t.Fatal("initial burst was not allowed")
	}
	if limiter.allow("192.0.2.1", now) {
		t.Fatal("request beyond burst was allowed")
	}
	if !limiter.allow("192.0.2.2", now) {
		t.Fatal("different source did not receive an independent bucket")
	}
	if limiter.allow("192.0.2.1", now.Add(500*time.Millisecond)) {
		t.Fatal("partial token was accepted")
	}
	if !limiter.allow("192.0.2.1", now.Add(time.Second)) {
		t.Fatal("refilled token was rejected")
	}
}

func TestNewTunnelLimiterSweepsAndBoundsSources(t *testing.T) {
	limiter := newNewTunnelLimiter(10, 2)
	now := time.Unix(100, 0)
	limiter.allow("old", now)
	limiter.allow("new", now.Add(2*time.Minute))
	if _, exists := limiter.buckets["old"]; exists {
		t.Fatal("idle source was not swept")
	}
	limiter = newNewTunnelLimiter(1, 1)
	for i := 0; i < newTunnelLimiterMaxSources; i++ {
		if !limiter.allow(string(rune(i+1)), now) {
			t.Fatalf("source %d rejected before table reached capacity", i)
		}
	}
	if limiter.allow("overflow", now) || len(limiter.buckets) != newTunnelLimiterMaxSources {
		t.Fatalf("source table was not bounded: entries=%d", len(limiter.buckets))
	}
}

func TestEngineRateLimitsOnlyNewTunnelsPerSourceIP(t *testing.T) {
	engine := NewEngine(Config{HostName: "server", NewTunnelsPerSecond: 1, NewTunnelBurst: 1})
	now := time.Unix(1000, 0)
	sccrq := func(id uint16) []byte {
		client := l2tp.NewControlChannel(0, 4)
		wire, err := client.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
			l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true),
			l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true),
			l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true),
			l2tp.StringAVP(l2tp.AttrHostName, "client", true),
			l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, id, true),
		}}, now)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	peer := testPeer("198.51.100.1:1701")
	first := sccrq(1)
	if _, err := engine.HandleDatagram(peer, first, now); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.HandleDatagram(peer, first, now); err != nil {
		t.Fatalf("retransmission was rate limited: %v", err)
	}
	if _, err := engine.HandleDatagram(testPeer("198.51.100.1:1702"), sccrq(2), now); !errors.Is(err, ErrNewTunnelRateLimited) {
		t.Fatalf("same-source new tunnel error=%v", err)
	}
	if _, err := engine.HandleDatagram(testPeer("198.51.100.2:1701"), sccrq(3), now); err != nil {
		t.Fatalf("different source was limited: %v", err)
	}
}

func TestEngineNewTunnelRateLimitDisabled(t *testing.T) {
	if NewEngine(Config{}).newTunnelRL != nil {
		t.Fatal("zero rate should disable the limiter")
	}
}

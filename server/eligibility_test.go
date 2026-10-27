package server

import (
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/ppp"
)

func TestSessionEligibilityPinsIdentity(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	eligible := e.SessionEligibility(ch.PeerTunnelID, sid)
	if !eligible() {
		t.Fatal("open session is ineligible")
	}
	if e.SessionEligibility(65535, 65535)() {
		t.Fatal("unknown session is eligible")
	}
	e.ClosePeer(peer)
	if eligible() {
		t.Fatal("closed session is eligible")
	}
	replacement, _, _, _ := dataSession(t)
	e.mu.Lock()
	e.tunnels[ch.PeerTunnelID] = replacement.tunnels[ch.PeerTunnelID]
	e.mu.Unlock()
	if eligible() {
		t.Fatal("old identity accepted reused numeric IDs")
	}
	if !e.SessionEligibility(ch.PeerTunnelID, sid)() {
		t.Fatal("replacement is ineligible")
	}
}

func TestSendableFollowsPPPPhaseUnderEngineLock(t *testing.T) {
	e, ch, peer, sid := dataSession(t)
	session := e.tunnels[ch.PeerTunnelID].sessions[sid]
	session.sendable.Store(false)
	if _, err := e.HandleDatagram(peer, dataWire(t, ch.PeerTunnelID, sid, 1), time.Now()); err != nil {
		t.Fatal(err)
	}
	if !session.sendable.Load() {
		t.Fatal("PPP-open session not marked sendable after handling")
	}
	e.mu.Lock()
	session.ppp.Phase = ppp.PhaseLCP
	e.mu.Unlock()
	_, _ = e.HandleDatagram(peer, dataWire(t, ch.PeerTunnelID, sid, 2), time.Now())
	if session.sendable.Load() {
		t.Fatal("session left PPP Open but stayed sendable")
	}
}

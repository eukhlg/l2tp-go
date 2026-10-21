package server

import "testing"

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

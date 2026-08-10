package l2tp

import (
	"errors"
	"testing"
)

func TestServerTunnelAndIncomingSessionLifecycle(t *testing.T) {
	tunnel := NewServerTunnel(ServerTunnelConfig{LocalTunnelID: 100, FirstSessionID: 200, HostName: "server", VendorName: "l2tp-go"})
	reply, err := tunnel.Handle(ControlMessage{Type: SCCRQ, AVPs: []AVP{
		Uint16AVP(AttrProtocolVersion, 0x0100, true),
		Uint16AVP(AttrAssignedTunnelID, 50, true),
		Uint32AVP(AttrFramingCap, 3, true),
		Uint32AVP(AttrBearerCap, 3, true),
		StringAVP(AttrHostName, "client", true),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.State != TunnelWaitConnect || tunnel.PeerTunnelID != 50 || reply == nil || reply.Type != SCCRP {
		t.Fatalf("tunnel=%#v reply=%#v", tunnel, reply)
	}
	assigned, ok := reply.Find(AttrAssignedTunnelID)
	if !ok {
		t.Fatal("SCCRP missing assigned tunnel ID")
	}
	id, err := assigned.Uint16()
	if err != nil || id != 100 {
		t.Fatalf("assigned ID=%d err=%v", id, err)
	}

	if reply, err = tunnel.Handle(ControlMessage{Type: SCCCN, TunnelID: 100}); err != nil || reply != nil {
		t.Fatalf("reply=%#v err=%v", reply, err)
	}
	if tunnel.State != TunnelEstablished {
		t.Fatalf("state=%d", tunnel.State)
	}

	reply, err = tunnel.Handle(ControlMessage{Type: ICRQ, TunnelID: 100, AVPs: []AVP{Uint16AVP(AttrAssignedSessionID, 70, true), Uint32AVP(AttrCallSerialNumber, 1, true)}})
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil || reply.Type != ICRP || reply.SessionID != 70 {
		t.Fatalf("reply=%#v", reply)
	}
	session, ok := tunnel.Session(200)
	if !ok || session.PeerID != 70 || session.State != SessionWaitConnect {
		t.Fatalf("session=%#v ok=%v", session, ok)
	}

	if _, err = tunnel.Handle(ControlMessage{Type: ICCN, TunnelID: 100, SessionID: 200}); err != nil {
		t.Fatal(err)
	}
	session, _ = tunnel.Session(200)
	if session.State != SessionEstablished {
		t.Fatalf("state=%d", session.State)
	}
	if _, err = tunnel.Handle(ControlMessage{Type: CDN, TunnelID: 100, SessionID: 200}); err != nil {
		t.Fatal(err)
	}
	if _, ok = tunnel.Session(200); ok {
		t.Fatal("session still exists")
	}
	if _, err = tunnel.Handle(ControlMessage{Type: StopCCN, TunnelID: 100}); err != nil {
		t.Fatal(err)
	}
	if tunnel.State != TunnelClosed {
		t.Fatalf("state=%d", tunnel.State)
	}
}

func TestServerTunnelRejectsBadTransitionsAndAttributes(t *testing.T) {
	newTunnel := func() *ServerTunnel { return NewServerTunnel(ServerTunnelConfig{LocalTunnelID: 1}) }
	if _, err := newTunnel().Handle(ControlMessage{Type: SCCCN, TunnelID: 1}); !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatal(err)
	}
	if _, err := newTunnel().Handle(ControlMessage{Type: SCCRQ, AVPs: []AVP{Uint16AVP(AttrProtocolVersion, 0x0100, true)}}); !errors.Is(err, ErrMissingAttribute) {
		t.Fatal(err)
	}
	if _, err := newTunnel().Handle(ControlMessage{Type: SCCRQ, AVPs: []AVP{Uint16AVP(AttrProtocolVersion, 0x0200, true), Uint16AVP(AttrAssignedTunnelID, 2, true)}}); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatal(err)
	}
	tunnel := newTunnel()
	tunnel.State = TunnelEstablished
	if _, err := tunnel.Handle(ControlMessage{Type: ICCN, TunnelID: 1, SessionID: 99}); !errors.Is(err, ErrUnknownSession) {
		t.Fatal(err)
	}
}

func TestServerTunnelAcceptsSCCRQWithoutOptionalBearerCapabilities(t *testing.T) {
	tunnel := NewServerTunnel(ServerTunnelConfig{LocalTunnelID: 1, HostName: "server"})
	reply, err := tunnel.Handle(ControlMessage{Type: SCCRQ, AVPs: []AVP{
		Uint16AVP(AttrProtocolVersion, 0x0100, true),
		Uint16AVP(AttrAssignedTunnelID, 2, true),
		Uint32AVP(AttrFramingCap, 3, true),
		StringAVP(AttrHostName, "macOS", true),
	}})
	if err != nil || reply == nil || reply.Type != SCCRP || tunnel.State != TunnelWaitConnect {
		t.Fatalf("reply=%#v state=%d err=%v", reply, tunnel.State, err)
	}
}

func TestServerTunnelAcceptsCDNAfterPPPTermination(t *testing.T) {
	tunnel := NewServerTunnel(ServerTunnelConfig{LocalTunnelID: 1})
	tunnel.State = TunnelEstablished
	if _, err := tunnel.Handle(ControlMessage{Type: CDN, TunnelID: 1, SessionID: 99}); err != nil {
		t.Fatalf("idempotent CDN rejected: %v", err)
	}
}

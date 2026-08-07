package server

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"l2tp-go/protocol/l2tp"
	"l2tp-go/protocol/ppp"
)

type testPeer string

func (p testPeer) Network() string { return "udp" }
func (p testPeer) String() string  { return string(p) }

func TestEngineTunnelSessionAndData(t *testing.T) {
	engine := NewEngine(Config{HostName: "server", FirstTunnelID: 100, FirstSessionID: 200, ReceiveWindow: 4})
	client := l2tp.NewControlChannel(0, 4)
	peer := testPeer("192.0.2.1:1701")
	now := time.Unix(100, 0)

	sccrq := l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true),
		l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true),
		l2tp.StringAVP(l2tp.AttrHostName, "client", true),
		l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 50, true),
	}}
	wire, err := client.Queue(sccrq, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	message := receiveOne(t, client, result)
	if message.Type != l2tp.SCCRP || message.TunnelID != 50 {
		t.Fatalf("SCCRP=%#v", message)
	}
	assigned, ok := message.Find(l2tp.AttrAssignedTunnelID)
	if !ok {
		t.Fatal("missing assigned tunnel ID")
	}
	serverTunnelID, err := assigned.Uint16()
	if err != nil || serverTunnelID != 100 {
		t.Fatalf("tunnel ID=%d err=%v", serverTunnelID, err)
	}
	client.PeerTunnelID = serverTunnelID

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.SCCCN}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	receiveAck(t, client, result)

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.ICRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrAssignedSessionID, 70, true),
		l2tp.Uint32AVP(l2tp.AttrCallSerialNumber, 1, true),
	}}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	message = receiveOne(t, client, result)
	if message.Type != l2tp.ICRP || message.SessionID != 70 {
		t.Fatalf("ICRP=%#v", message)
	}
	assigned, _ = message.Find(l2tp.AttrAssignedSessionID)
	serverSessionID, err := assigned.Uint16()
	if err != nil || serverSessionID != 200 {
		t.Fatalf("session ID=%d err=%v", serverSessionID, err)
	}

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.ICCN, SessionID: serverSessionID}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	receiveAck(t, client, result)

	frameWire, err := (ppp.Frame{Protocol: 0x0021, Payload: []byte{0x45, 0, 0, 20}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	dataWire, err := (l2tp.Packet{TunnelID: serverTunnelID, SessionID: serverSessionID, Payload: frameWire}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	result, err = engine.HandleDatagram(peer, dataWire, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Data == nil || result.Data.PPP.Protocol != 0x0021 || !bytes.Equal(result.Data.PPP.Payload, []byte{0x45, 0, 0, 20}) {
		t.Fatalf("data=%#v", result.Data)
	}
}

func TestEngineRejectsUnknownTunnelAndChangedPeer(t *testing.T) {
	engine := NewEngine(Config{})
	data, err := (l2tp.Packet{TunnelID: 99, SessionID: 1, Payload: []byte{0x21}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.HandleDatagram(testPeer("one"), data, time.Time{}); !errors.Is(err, ErrUnknownTunnel) {
		t.Fatal(err)
	}

	client := l2tp.NewControlChannel(0, 1)
	wire, _ := client.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 1, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 1, true), l2tp.StringAVP(l2tp.AttrHostName, "c", true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 2, true),
	}}, time.Time{})
	result, err := engine.HandleDatagram(testPeer("one"), wire, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	response, _ := l2tp.DecodeControlMessage(result.Replies[0])
	assigned, _ := response.Find(l2tp.AttrAssignedTunnelID)
	id, _ := assigned.Uint16()
	probe, _ := (l2tp.ControlMessage{Type: l2tp.SCCCN, TunnelID: id, Ns: 1, Nr: 1}).MarshalBinary()
	if _, err := engine.HandleDatagram(testPeer("two"), probe, time.Time{}); !errors.Is(err, ErrPeerAddress) {
		t.Fatal(err)
	}
}

func TestEngineDoesNotAckZLB(t *testing.T) {
	engine, client, peer, now := establishTunnel(t)
	zlb, err := client.Ack()
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, zlb, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Replies) != 0 {
		t.Fatalf("ZLB produced %d replies", len(result.Replies))
	}
}

func TestMalformedSCCRQDoesNotLeakTunnel(t *testing.T) {
	engine := NewEngine(Config{FirstTunnelID: 1})
	client := l2tp.NewControlChannel(0, 1)
	wire, err := client.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 2, true),
	}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.HandleDatagram(testPeer("peer"), wire, time.Time{}); !errors.Is(err, l2tp.ErrMissingAttribute) {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine.TunnelCount() != 0 {
		t.Fatalf("tunnel count = %d", engine.TunnelCount())
	}
}

func establishTunnel(t *testing.T) (*Engine, *l2tp.ControlChannel, testPeer, time.Time) {
	t.Helper()
	engine := NewEngine(Config{HostName: "server", FirstTunnelID: 100, ReceiveWindow: 4})
	client := l2tp.NewControlChannel(0, 4)
	peer, now := testPeer("192.0.2.1:1701"), time.Unix(100, 0)
	wire, err := client.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true), l2tp.StringAVP(l2tp.AttrHostName, "client", true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 50, true),
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	message := receiveOne(t, client, result)
	assigned, _ := message.Find(l2tp.AttrAssignedTunnelID)
	client.PeerTunnelID, _ = assigned.Uint16()
	wire, err = client.Queue(l2tp.ControlMessage{Type: l2tp.SCCCN}, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	receiveAck(t, client, result)
	return engine, client, peer, now
}

func receiveOne(t *testing.T, channel *l2tp.ControlChannel, result Result) l2tp.ControlMessage {
	t.Helper()
	if len(result.Replies) != 1 {
		t.Fatalf("replies=%d", len(result.Replies))
	}
	message, err := channel.Receive(result.Replies[0])
	if err != nil || message == nil {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	return *message
}

func receiveAck(t *testing.T, channel *l2tp.ControlChannel, result Result) {
	t.Helper()
	if len(result.Replies) != 1 {
		t.Fatalf("replies=%d", len(result.Replies))
	}
	message, err := channel.Receive(result.Replies[0])
	if err != nil || message != nil {
		t.Fatalf("message=%#v err=%v", message, err)
	}
}

func TestPeerKey(t *testing.T) {
	if peerKey(nil) != "" {
		t.Fatal("nil peer has nonempty key")
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1701}
	if peerKey(addr) == "" {
		t.Fatal("UDP peer has empty key")
	}
}

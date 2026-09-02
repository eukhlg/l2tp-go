package server

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
)

func TestEngineDebugTraceMalformedDatagram(t *testing.T) {
	var debugLogs, traceLogs []string
	engine := NewEngine(Config{
		Debugf: func(format string, args ...any) { debugLogs = append(debugLogs, fmt.Sprintf(format, args...)) },
		Tracef: func(format string, args ...any) { traceLogs = append(traceLogs, fmt.Sprintf(format, args...)) },
	})
	if _, err := engine.HandleDatagram(testPeer("peer"), []byte{1}, time.Time{}); err == nil {
		t.Fatal("malformed datagram accepted")
	}
	if len(debugLogs) != 1 || !strings.Contains(debugLogs[0], "decode_error") {
		t.Fatalf("debug logs=%q", debugLogs)
	}
	if len(traceLogs) != 1 || !strings.Contains(traceLogs[0], "udp rx") {
		t.Fatalf("trace logs=%q", traceLogs)
	}
	for _, entry := range append(debugLogs, traceLogs...) {
		if strings.Contains(entry, "010203") {
			t.Fatalf("payload leaked: %s", entry)
		}
	}
}

type testPeer string

func (p testPeer) Network() string { return "udp" }
func (p testPeer) String() string  { return string(p) }

func TestEngineTunnelSessionAndData(t *testing.T) {
	pool, err := NewAddressPool(netip.MustParsePrefix("10.0.0.0/24"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(Config{HostName: "server", FirstTunnelID: 100, FirstSessionID: 200, ReceiveWindow: 4, AddressPool: pool, MaxSessionsPerTunnel: 1, MaxSessionsPerUser: 1, PPP: &ppp.SessionConfig{
		ServerAddress: netip.MustParseAddr("10.0.0.1"), ClientAddress: netip.MustParseAddr("10.0.0.2"),
		PrimaryDNS: netip.MustParseAddr("1.1.1.1"), Authenticate: ppp.StaticCredentials("alice", "secret"),
	}})
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

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.ICRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrAssignedSessionID, 71, true),
		l2tp.Uint32AVP(l2tp.AttrCallSerialNumber, 2, true),
	}}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	if rejected := receiveOne(t, client, result); rejected.Type != l2tp.CDN || rejected.SessionID != 71 {
		t.Fatalf("session rejection=%#v", rejected)
	}

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.ICCN, SessionID: serverSessionID}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Replies) != 2 {
		t.Fatalf("ICCN replies=%d", len(result.Replies))
	}
	receiveAck(t, client, Result{Replies: result.Replies[:1]})
	serverLCP := decodePPPControlDatagram(t, result.Replies[1])

	peerLCPData, _ := ppp.EncodeOptions(ppp.Option{Type: 1, Value: []byte{0x05, 0xdc}})
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolLCP, ppp.ControlPacket{Code: ppp.ConfigureRequest, Identifier: 4, Data: peerLCPData})
	if got := decodePPPControlDatagram(t, result.Replies[0]); got.Code != ppp.ConfigureAck {
		t.Fatalf("LCP reply=%#v", got)
	}
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolLCP, ppp.ControlPacket{Code: ppp.ConfigureAck, Identifier: serverLCP.Identifier, Data: serverLCP.Data})
	if len(result.Replies) != 0 {
		t.Fatalf("LCP ACK replies=%d", len(result.Replies))
	}

	papData := append([]byte{5}, []byte("alice")...)
	papData = append(papData, 6)
	papData = append(papData, []byte("secret")...)
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolPAP, ppp.ControlPacket{Code: 1, Identifier: 5, Data: papData})
	if len(result.Replies) != 2 || decodePPPControlDatagram(t, result.Replies[0]).Code != 2 {
		t.Fatalf("PAP replies=%d", len(result.Replies))
	}
	serverIPCP := decodePPPControlDatagram(t, result.Replies[1])
	clientIPCPData, _ := ppp.EncodeOptions(ppp.IPv4Option(3, netip.MustParseAddr("10.0.0.2")))
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolIPCP, ppp.ControlPacket{Code: ppp.ConfigureRequest, Identifier: 6, Data: clientIPCPData})
	if got := decodePPPControlDatagram(t, result.Replies[0]); got.Code != ppp.ConfigureAck {
		t.Fatalf("IPCP reply=%#v", got)
	}
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolIPCP, ppp.ControlPacket{Code: ppp.ConfigureAck, Identifier: serverIPCP.Identifier, Data: serverIPCP.Data})
	if len(result.Replies) != 0 {
		t.Fatalf("IPCP ACK replies=%d", len(result.Replies))
	}
	if result.Opened == nil || result.Opened.Address.String() != "10.0.0.2" || result.Opened.Username != "alice" || !result.Opened.Connected {
		t.Fatalf("opened=%#v", result.Opened)
	}

	ipv4 := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1}
	frameWire, err := (ppp.Frame{Protocol: 0x0021, Payload: ipv4}).MarshalBinary()
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
	if result.Data == nil || result.Data.PPP.Protocol != 0x0021 || !bytes.Equal(result.Data.PPP.Payload, ipv4) {
		t.Fatalf("data=%#v", result.Data)
	}
	outbound, err := engine.SendIPv4(serverTunnelID, serverSessionID, []byte{0x45, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	outPacket, err := l2tp.DecodePacket(outbound.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if outPacket.TunnelID != 50 || outPacket.SessionID != 70 {
		t.Fatalf("outbound=%#v", outPacket)
	}
	if pool.InUse() != 1 || engine.userSessions["alice"] != 1 {
		t.Fatalf("leases=%d users=%#v", pool.InUse(), engine.userSessions)
	}
	closed := engine.ClosePeer(peer)
	if len(closed) != 1 || !closed[0].Connected || closed[0].Address.String() != "10.0.0.2" || engine.TunnelCount() != 0 {
		t.Fatalf("closed=%#v tunnels=%d", closed, engine.TunnelCount())
	}
	if pool.InUse() != 0 || len(engine.userSessions) != 0 {
		t.Fatalf("leases=%d users=%#v", pool.InUse(), engine.userSessions)
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

func TestFreshSCCRQReplacesEstablishedTunnel(t *testing.T) {
	engine, _, peer, now := establishTunnel(t)
	client := l2tp.NewControlChannel(0, 4)
	wire, err := client.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true),
		l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true),
		l2tp.StringAVP(l2tp.AttrHostName, "restarted-client", true),
		l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 51, true),
	}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, wire, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	response := receiveOne(t, client, result)
	assigned, ok := response.Find(l2tp.AttrAssignedTunnelID)
	if !ok {
		t.Fatal("replacement SCCRP has no assigned tunnel ID")
	}
	serverID, err := assigned.Uint16()
	if err != nil || response.Type != l2tp.SCCRP || serverID != 101 || engine.TunnelCount() != 1 {
		t.Fatalf("response=%#v serverID=%d tunnels=%d err=%v", response, serverID, engine.TunnelCount(), err)
	}
}

func TestMalformedSCCRQDoesNotReplaceEstablishedTunnel(t *testing.T) {
	engine, _, peer, now := establishTunnel(t)
	client := l2tp.NewControlChannel(0, 1)
	wire, err := client.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 51, true),
	}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.HandleDatagram(peer, wire, now.Add(time.Second)); !errors.Is(err, l2tp.ErrMissingAttribute) {
		t.Fatalf("err=%v", err)
	}
	if engine.TunnelCount() != 1 {
		t.Fatalf("tunnel count=%d", engine.TunnelCount())
	}
}

func TestEngineShutdownSendsStopCCN(t *testing.T) {
	engine, client, peer, _ := establishTunnel(t)
	packets, closed, err := engine.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 || packets[0].Peer.String() != peer.String() || len(closed) != 0 || engine.TunnelCount() != 0 {
		t.Fatalf("packets=%#v closed=%#v tunnels=%d", packets, closed, engine.TunnelCount())
	}
	message, err := client.Receive(packets[0].Payload)
	if err != nil || message == nil || message.Type != l2tp.StopCCN {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	resultCode, ok := message.Find(l2tp.AttrResultCode)
	if !ok {
		t.Fatal("StopCCN has no result code")
	}
	code, err := resultCode.Uint16()
	if err != nil || code != 6 {
		t.Fatalf("result code=%d err=%v", code, err)
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

func sendPPPControl(t *testing.T, engine *Engine, peer net.Addr, now time.Time, tunnelID, sessionID, protocol uint16, control ppp.ControlPacket) Result {
	t.Helper()
	payload, err := control.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := (ppp.Frame{Protocol: protocol, Payload: payload}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (l2tp.Packet{TunnelID: tunnelID, SessionID: sessionID, Payload: frame}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodePPPControlDatagram(t *testing.T, wire []byte) ppp.ControlPacket {
	t.Helper()
	packet, err := l2tp.DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := ppp.DecodeFrame(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	control, err := ppp.DecodeControlPacket(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return control
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

package ppp

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestSessionLCPPAPIPCPAndIPv4(t *testing.T) {
	session, err := NewSession(SessionConfig{
		ServerAddress: netip.MustParseAddr("10.0.0.1"), ClientAddress: netip.MustParseAddr("10.0.0.2"),
		PrimaryDNS: netip.MustParseAddr("1.1.1.1"), SecondaryDNS: netip.MustParseAddr("8.8.8.8"),
		Authenticate: StaticCredentials("alice", "secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	start, err := session.Start()
	if err != nil || len(start) != 1 || start[0].Protocol != ProtocolLCP {
		t.Fatalf("start=%#v err=%v", start, err)
	}
	localRequest := decodeControl(t, start[0])

	peerOptions, _ := EncodeOptions(Option{Type: 1, Value: []byte{0x05, 0xdc}})
	result := handleControl(t, session, ProtocolLCP, ControlPacket{Code: ConfigureRequest, Identifier: 9, Data: peerOptions})
	if got := decodeControl(t, result.Frames[0]); got.Code != ConfigureAck || !bytes.Equal(got.Data, peerOptions) {
		t.Fatalf("ack=%#v", got)
	}
	handleControl(t, session, ProtocolLCP, ControlPacket{Code: ConfigureAck, Identifier: localRequest.Identifier, Data: localRequest.Data})
	if session.Phase != PhaseAuthenticate {
		t.Fatalf("phase=%d", session.Phase)
	}

	papData := append([]byte{5}, []byte("alice")...)
	papData = append(papData, 6)
	papData = append(papData, []byte("secret")...)
	result = handleControl(t, session, ProtocolPAP, ControlPacket{Code: 1, Identifier: 3, Data: papData})
	if len(result.Frames) != 2 || decodeControl(t, result.Frames[0]).Code != 2 || session.Phase != PhaseIPCP {
		t.Fatalf("result=%#v phase=%d", result, session.Phase)
	}
	serverIPCP := decodeControl(t, result.Frames[1])

	requested, _ := EncodeOptions(IPv4Option(3, netip.IPv4Unspecified()), IPv4Option(129, netip.IPv4Unspecified()))
	result = handleControl(t, session, ProtocolIPCP, ControlPacket{Code: ConfigureRequest, Identifier: 4, Data: requested})
	if nak := decodeControl(t, result.Frames[0]); nak.Code != ConfigureNak {
		t.Fatalf("response=%#v", nak)
	}
	corrected, _ := EncodeOptions(IPv4Option(3, netip.MustParseAddr("10.0.0.2")), IPv4Option(129, netip.MustParseAddr("1.1.1.1")))
	handleControl(t, session, ProtocolIPCP, ControlPacket{Code: ConfigureRequest, Identifier: 5, Data: corrected})
	handleControl(t, session, ProtocolIPCP, ControlPacket{Code: ConfigureAck, Identifier: serverIPCP.Identifier, Data: serverIPCP.Data})
	if session.Phase != PhaseOpen {
		t.Fatalf("phase=%d", session.Phase)
	}

	ip := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1}
	result, err = session.Handle(Frame{Protocol: ProtocolIPv4, Payload: ip})
	if err != nil || !bytes.Equal(result.IPv4, ip) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestSessionRejectsSpoofedIPv4Source(t *testing.T) {
	session, _ := NewSession(SessionConfig{ServerAddress: netip.MustParseAddr("10.0.0.1"), ClientAddress: netip.MustParseAddr("10.0.0.2"), Authenticate: StaticCredentials("u", "p")})
	session.Phase = PhaseOpen
	packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 99, 10, 0, 0, 1}
	if _, err := session.Handle(Frame{Protocol: ProtocolIPv4, Payload: packet}); err != ErrSourceAddress {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionRejectsBadCredentials(t *testing.T) {
	session, err := NewSession(SessionConfig{ServerAddress: netip.MustParseAddr("10.0.0.1"), ClientAddress: netip.MustParseAddr("10.0.0.2"), Authenticate: StaticCredentials("u", "p")})
	if err != nil {
		t.Fatal(err)
	}
	session.Phase = PhaseAuthenticate
	result := handleControl(t, session, ProtocolPAP, ControlPacket{Code: 1, Identifier: 1, Data: []byte{1, 'u', 3, 'b', 'a', 'd'}})
	if session.Phase != PhaseClosed || decodeControl(t, result.Frames[0]).Code != 3 {
		t.Fatalf("phase=%d result=%#v", session.Phase, result)
	}
}

func TestIPCPRejectsUnknownOption(t *testing.T) {
	session, _ := NewSession(SessionConfig{ServerAddress: netip.MustParseAddr("10.0.0.1"), ClientAddress: netip.MustParseAddr("10.0.0.2"), Authenticate: StaticCredentials("u", "p")})
	session.Phase = PhaseIPCP
	data, _ := EncodeOptions(Option{Type: 2, Value: []byte{0, 0, 0, 0}})
	result := handleControl(t, session, ProtocolIPCP, ControlPacket{Code: ConfigureRequest, Identifier: 1, Data: data})
	if decodeControl(t, result.Frames[0]).Code != ConfigureReject {
		t.Fatalf("result=%#v", result)
	}
}

func decodeControl(t *testing.T, frame Frame) ControlPacket {
	t.Helper()
	packet, err := DecodeControlPacket(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func handleControl(t *testing.T, session *Session, protocol uint16, packet ControlPacket) SessionResult {
	t.Helper()
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.Handle(Frame{Protocol: protocol, Payload: wire})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

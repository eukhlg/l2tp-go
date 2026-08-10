package server

import (
	"context"
	"net"
	"testing"
	"time"

	"l2tp-go/protocol/l2tp"
)

func TestServerLoopbackHandshake(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Conn: listener, Engine: NewEngine(Config{HostName: "server", FirstTunnelID: 10}), RetransmitTimeout: time.Second, MaxRetries: 2}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	channel := l2tp.NewControlChannel(0, 1)
	wire, err := channel.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 1, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 1, true), l2tp.StringAVP(l2tp.AttrHostName, "client", true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 20, true),
	}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message, err := channel.Receive(buffer[:n])
	if err != nil || message == nil || message.Type != l2tp.SCCRP {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	cancel()
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message, err = channel.Receive(buffer[:n])
	if err != nil || message == nil || message.Type != l2tp.StopCCN {
		t.Fatalf("shutdown message=%#v err=%v", message, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTeardownControlDatagramClassification(t *testing.T) {
	for _, kind := range []l2tp.MessageType{l2tp.CDN, l2tp.StopCCN} {
		wire, err := (l2tp.ControlMessage{Type: kind, TunnelID: 1, SessionID: 1}).MarshalBinary()
		if err != nil || !isTeardownControlDatagram(wire) {
			t.Fatalf("type=%s classified=false err=%v", kind, err)
		}
	}
	wire, err := (l2tp.ControlMessage{Type: l2tp.Hello, TunnelID: 1}).MarshalBinary()
	if err != nil || isTeardownControlDatagram(wire) {
		t.Fatalf("Hello classified as teardown: err=%v", err)
	}
}

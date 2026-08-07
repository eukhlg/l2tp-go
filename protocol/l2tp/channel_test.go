package l2tp

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestControlChannelQueueAndAcknowledge(t *testing.T) {
	now := time.Unix(100, 0)
	c := NewControlChannel(42, 2)
	wire, err := c.Queue(ControlMessage{Type: SCCRP}, now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if p.TunnelID != 42 || p.Ns != 0 || p.Nr != 0 || c.Pending() != 1 {
		t.Fatalf("packet=%#v pending=%d", p, c.Pending())
	}
	ack, err := (Packet{Control: true, HasSequence: true, Ns: 0, Nr: 1}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	message, err := c.Receive(ack)
	if err != nil || message != nil || c.Pending() != 0 {
		t.Fatalf("message=%#v err=%v pending=%d", message, err, c.Pending())
	}
}

func TestControlChannelReceiveAndDuplicate(t *testing.T) {
	c := NewControlChannel(7, 1)
	peer := ControlMessage{Type: SCCCN, TunnelID: 9, Ns: 0, Nr: 0}
	wire, err := peer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	message, err := c.Receive(wire)
	if err != nil || message == nil || message.Type != SCCCN {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	message, err = c.Receive(wire)
	if err != nil || message != nil {
		t.Fatalf("duplicate message=%#v err=%v", message, err)
	}
	ack, err := c.Ack()
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePacket(ack)
	if err != nil {
		t.Fatal(err)
	}
	if p.Ns != 0 || p.Nr != 1 || len(p.AVPs) != 0 {
		t.Fatalf("unexpected ACK: %#v", p)
	}
}

func TestControlChannelWindowAndOrdering(t *testing.T) {
	c := NewControlChannel(1, 1)
	if _, err := c.Queue(ControlMessage{Type: Hello}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Queue(ControlMessage{Type: Hello}, time.Time{}); !errors.Is(err, ErrWindowFull) {
		t.Fatalf("unexpected error: %v", err)
	}
	outOfOrder, err := (ControlMessage{Type: Hello, Ns: 2}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receive(outOfOrder); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestControlChannelRejectsAcknowledgementOfUnsentPacket(t *testing.T) {
	c := NewControlChannel(1, 1)
	wire, err := (Packet{Control: true, HasSequence: true, Nr: 1}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receive(wire); !errors.Is(err, ErrInvalidAck) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZLBDoesNotConsumeSequenceNumber(t *testing.T) {
	c := NewControlChannel(1, 1)
	zlb, err := (Packet{Control: true, HasSequence: true}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receive(zlb); err != nil {
		t.Fatal(err)
	}
	message, err := (ControlMessage{Type: Hello}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Receive(message); err != nil || got == nil || got.Type != Hello {
		t.Fatalf("message=%#v err=%v", got, err)
	}
}

func TestZLBMayOvertakeSequencedMessage(t *testing.T) {
	c := NewControlChannel(1, 1)
	zlb, err := (Packet{Control: true, HasSequence: true, Ns: 3}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if message, err := c.Receive(zlb); err != nil || message != nil {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	message, err := (ControlMessage{Type: Hello, Ns: 0}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Receive(message); err != nil || got == nil || got.Type != Hello {
		t.Fatalf("message=%#v err=%v", got, err)
	}
}

func TestControlChannelRetransmission(t *testing.T) {
	start := time.Unix(100, 0)
	c := NewControlChannel(1, 1)
	wire, err := c.Queue(ControlMessage{Type: SCCRP}, start)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Retransmit(start.Add(time.Second), 2*time.Second, 1)
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%x err=%v", got, err)
	}
	got, err = c.Retransmit(start.Add(2*time.Second), 2*time.Second, 1)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], wire) {
		t.Fatalf("got=%x err=%v", got, err)
	}
	if _, err := c.Retransmit(start.Add(4*time.Second), 2*time.Second, 1); !errors.Is(err, ErrRetryExhausted) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQueueUntrackedBypassesFullWindow(t *testing.T) {
	c := NewControlChannel(9, 1)
	if _, err := c.Queue(ControlMessage{Type: Hello}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	wire, err := c.QueueUntracked(ControlMessage{Type: StopCCN})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeControlMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != StopCCN || message.TunnelID != 9 || message.Ns != 1 || c.Pending() != 1 {
		t.Fatalf("message=%#v pending=%d", message, c.Pending())
	}
}

func TestSequenceBeforeWraparound(t *testing.T) {
	if !sequenceBefore(0xffff, 0) || sequenceBefore(0, 0xffff) {
		t.Fatal("bad wraparound comparison")
	}
}

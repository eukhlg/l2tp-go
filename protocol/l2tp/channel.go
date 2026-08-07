package l2tp

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrWindowFull     = errors.New("l2tp: control transmit window is full")
	ErrOutOfOrder     = errors.New("l2tp: out-of-order control packet")
	ErrInvalidAck     = errors.New("l2tp: invalid control acknowledgement")
	ErrRetryExhausted = errors.New("l2tp: control packet retry limit exhausted")
)

type pendingControl struct {
	ns      uint16
	wire    []byte
	sentAt  time.Time
	retries int
}

// ControlChannel implements the reliable, sequenced transport for one L2TP
// tunnel. It is deliberately independent from socket I/O and timers.
type ControlChannel struct {
	PeerTunnelID uint16
	SendWindow   uint16
	nextSend     uint16
	nextReceive  uint16
	pending      []pendingControl
}

func NewControlChannel(peerTunnelID, sendWindow uint16) *ControlChannel {
	if sendWindow == 0 {
		sendWindow = 1
	}
	return &ControlChannel{PeerTunnelID: peerTunnelID, SendWindow: sendWindow}
}

// Queue assigns sequence numbers, encodes a message, and retains it until its
// Ns is cumulatively acknowledged by the peer's Nr.
func (c *ControlChannel) Queue(message ControlMessage, now time.Time) ([]byte, error) {
	if len(c.pending) >= int(c.SendWindow) {
		return nil, ErrWindowFull
	}
	message.TunnelID = c.PeerTunnelID
	message.Ns, message.Nr = c.nextSend, c.nextReceive
	wire, err := message.MarshalBinary()
	if err != nil {
		return nil, err
	}
	c.pending = append(c.pending, pendingControl{ns: c.nextSend, wire: wire, sentAt: now})
	c.nextSend++
	return append([]byte(nil), wire...), nil
}

// QueueUntracked encodes one sequenced control message without retaining it
// for retransmission or applying the peer's transmit-window limit. It is
// intended for a final StopCCN sent while the local process is shutting down.
func (c *ControlChannel) QueueUntracked(message ControlMessage) ([]byte, error) {
	message.TunnelID = c.PeerTunnelID
	message.Ns, message.Nr = c.nextSend, c.nextReceive
	wire, err := message.MarshalBinary()
	if err != nil {
		return nil, err
	}
	c.nextSend++
	return wire, nil
}

// Receive processes acknowledgements and, when present, returns one newly
// accepted control message. A nil message denotes a zero-length body (ZLB) ACK
// or a duplicate that has already been delivered.
func (c *ControlChannel) Receive(wire []byte) (*ControlMessage, error) {
	packet, err := DecodePacket(wire)
	if err != nil {
		return nil, err
	}
	if !packet.Control {
		return nil, ErrNotControlMessage
	}
	if sequenceBefore(c.nextSend, packet.Nr) {
		return nil, fmt.Errorf("%w: got Nr %d, next Ns is %d", ErrInvalidAck, packet.Nr, c.nextSend)
	}
	c.acknowledge(packet.Nr)
	if len(packet.AVPs) == 0 {
		// A ZLB carries the sender's current Ns but does not consume a
		// sequence number. UDP may deliver it before the control message
		// whose Ns it reflects, so only use its Nr acknowledgement here.
		return nil, nil
	}
	if packet.Ns != c.nextReceive {
		if sequenceBefore(packet.Ns, c.nextReceive) {
			return nil, nil // Retransmitted packet; acknowledge but do not redeliver.
		}
		return nil, fmt.Errorf("%w: got Ns %d, want %d", ErrOutOfOrder, packet.Ns, c.nextReceive)
	}
	c.nextReceive++
	message, err := decodeControlPacket(packet)
	if err != nil {
		return nil, err
	}
	return &message, nil
}

// Ack creates a ZLB acknowledgement. ZLBs do not consume an Ns value and are
// never placed in the retransmission queue.
func (c *ControlChannel) Ack() ([]byte, error) {
	return (Packet{Control: true, TunnelID: c.PeerTunnelID, HasSequence: true, Ns: c.nextSend, Nr: c.nextReceive}).MarshalBinary()
}

// Retransmit returns copies of packets whose retry deadline has elapsed.
func (c *ControlChannel) Retransmit(now time.Time, timeout time.Duration, maxRetries int) ([][]byte, error) {
	var result [][]byte
	for i := range c.pending {
		p := &c.pending[i]
		if now.Sub(p.sentAt) < timeout {
			continue
		}
		if p.retries >= maxRetries {
			return nil, fmt.Errorf("%w: Ns %d", ErrRetryExhausted, p.ns)
		}
		p.retries++
		p.sentAt = now
		result = append(result, append([]byte(nil), p.wire...))
	}
	return result, nil
}

func (c *ControlChannel) Pending() int { return len(c.pending) }

func (c *ControlChannel) acknowledge(nr uint16) {
	for len(c.pending) != 0 && sequenceBefore(c.pending[0].ns, nr) {
		c.pending = c.pending[1:]
	}
}

// sequenceBefore compares 16-bit sequence numbers in a window smaller than
// half the sequence space, including across wraparound.
func sequenceBefore(a, b uint16) bool { return int16(a-b) < 0 }

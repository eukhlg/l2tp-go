// Package ppp implements the PPP wire framing used inside an L2TP session.
package ppp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Address byte = 0xff
	Control byte = 0x03
)

var ErrShortFrame = errors.New("ppp: frame is too short")

// Frame is a decoded PPP frame. L2TP carries frames without an FCS.
type Frame struct {
	Protocol uint16
	Payload  []byte
}

// DecodeFrame accepts both address-and-control-field-compressed and protocol-
// field-compressed frames, as negotiated by PPP.
func DecodeFrame(b []byte) (Frame, error) {
	if len(b) >= 2 && b[0] == Address && b[1] == Control {
		b = b[2:]
	}
	if len(b) == 0 {
		return Frame{}, ErrShortFrame
	}

	var protocol uint16
	if b[0]&1 != 0 { // RFC 1661 protocol-field compression.
		protocol = uint16(b[0])
		b = b[1:]
	} else {
		if len(b) < 2 {
			return Frame{}, ErrShortFrame
		}
		protocol = binary.BigEndian.Uint16(b[:2])
		b = b[2:]
	}
	if !validProtocol(protocol) {
		return Frame{}, fmt.Errorf("ppp: invalid protocol %#x", protocol)
	}
	return Frame{Protocol: protocol, Payload: append([]byte(nil), b...)}, nil
}

// MarshalBinary returns an uncompressed PPP frame without an FCS.
func (f Frame) MarshalBinary() ([]byte, error) {
	if !validProtocol(f.Protocol) {
		return nil, fmt.Errorf("ppp: invalid protocol %#x", f.Protocol)
	}
	out := make([]byte, 4+len(f.Payload))
	out[0], out[1] = Address, Control
	binary.BigEndian.PutUint16(out[2:4], f.Protocol)
	copy(out[4:], f.Payload)
	return out, nil
}

// RFC 1661 requires the first protocol octet to be even and the second odd.
func validProtocol(protocol uint16) bool {
	return protocol != 0 && protocol&0x0101 == 0x0001
}

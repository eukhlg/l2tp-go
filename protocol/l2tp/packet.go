// Package l2tp implements strict L2TPv2 control and data packet codecs.
package l2tp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	flagType     = 0x8000
	flagLength   = 0x4000
	flagSequence = 0x0800
	flagOffset   = 0x0200
	version2     = 0x0002
)

var (
	ErrShortPacket   = errors.New("l2tp: packet is too short")
	ErrBadVersion    = errors.New("l2tp: unsupported version")
	ErrInvalidPacket = errors.New("l2tp: invalid packet")
)

type Packet struct {
	Control             bool
	TunnelID, SessionID uint16
	HasSequence         bool
	Ns, Nr              uint16
	AVPs                []AVP
	Payload             []byte
}

func (p Packet) MarshalBinary() ([]byte, error) {
	if p.Control && !p.HasSequence {
		return nil, fmt.Errorf("%w: control packet requires sequence numbers", ErrInvalidPacket)
	}
	body := append([]byte(nil), p.Payload...)
	if p.Control {
		body = body[:0]
		for _, avp := range p.AVPs {
			wire, err := avp.MarshalBinary()
			if err != nil {
				return nil, err
			}
			body = append(body, wire...)
		}
	}
	headerLen := 6
	flags := uint16(version2)
	if p.Control {
		flags |= flagType | flagLength
	}
	if p.HasSequence {
		flags |= flagSequence
		headerLen += 4
	}
	if p.Control {
		headerLen += 2
	}
	total := headerLen + len(body)
	if total > 0xffff {
		return nil, fmt.Errorf("%w: packet too large", ErrInvalidPacket)
	}
	out := make([]byte, total)
	binary.BigEndian.PutUint16(out[:2], flags)
	pos := 2
	if p.Control {
		binary.BigEndian.PutUint16(out[pos:pos+2], uint16(total))
		pos += 2
	}
	binary.BigEndian.PutUint16(out[pos:pos+2], p.TunnelID)
	pos += 2
	binary.BigEndian.PutUint16(out[pos:pos+2], p.SessionID)
	pos += 2
	if p.HasSequence {
		binary.BigEndian.PutUint16(out[pos:pos+2], p.Ns)
		binary.BigEndian.PutUint16(out[pos+2:pos+4], p.Nr)
		pos += 4
	}
	copy(out[pos:], body)
	return out, nil
}

func DecodePacket(b []byte) (Packet, error) {
	if len(b) < 6 {
		return Packet{}, ErrShortPacket
	}
	flags := binary.BigEndian.Uint16(b[:2])
	if flags&0x000f != version2 {
		return Packet{}, ErrBadVersion
	}
	if flags&0x34f0 != 0 {
		return Packet{}, fmt.Errorf("%w: reserved flag bits", ErrInvalidPacket)
	}
	control := flags&flagType != 0
	if control && (flags&flagLength == 0 || flags&flagSequence == 0) {
		return Packet{}, fmt.Errorf("%w: incomplete control header", ErrInvalidPacket)
	}
	pos, end := 2, len(b)
	if flags&flagLength != 0 {
		if len(b) < pos+2 {
			return Packet{}, ErrShortPacket
		}
		end = int(binary.BigEndian.Uint16(b[pos : pos+2]))
		pos += 2
		if end < pos || end > len(b) {
			return Packet{}, fmt.Errorf("%w: bad declared length %d", ErrInvalidPacket, end)
		}
	}
	if end < pos+4 {
		return Packet{}, ErrShortPacket
	}
	p := Packet{Control: control, TunnelID: binary.BigEndian.Uint16(b[pos : pos+2]), SessionID: binary.BigEndian.Uint16(b[pos+2 : pos+4])}
	pos += 4
	if flags&flagSequence != 0 {
		if end < pos+4 {
			return Packet{}, ErrShortPacket
		}
		p.HasSequence = true
		p.Ns = binary.BigEndian.Uint16(b[pos : pos+2])
		p.Nr = binary.BigEndian.Uint16(b[pos+2 : pos+4])
		pos += 4
	}
	if flags&flagOffset != 0 {
		if end < pos+2 {
			return Packet{}, ErrShortPacket
		}
		offset := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		pos += 2
		if end < pos+offset {
			return Packet{}, fmt.Errorf("%w: bad offset", ErrInvalidPacket)
		}
		pos += offset
	}
	if control {
		var err error
		p.AVPs, err = decodeAVPs(b[pos:end])
		if err != nil {
			return Packet{}, err
		}
	} else {
		p.Payload = append([]byte(nil), b[pos:end]...)
	}
	return p, nil
}

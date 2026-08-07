package l2tp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const avpHeaderLen = 6

var (
	ErrShortAVP   = errors.New("l2tp: AVP is too short")
	ErrHiddenAVP  = errors.New("l2tp: hidden AVP is not supported")
	ErrInvalidAVP = errors.New("l2tp: invalid AVP")
)

// AVP is an L2TP Attribute-Value Pair. VendorID zero denotes an IETF AVP.
type AVP struct {
	Mandatory bool
	Hidden    bool
	VendorID  uint16
	Type      uint16
	Value     []byte
}

func (a AVP) MarshalBinary() ([]byte, error) {
	length := avpHeaderLen + len(a.Value)
	if length > 0x03ff {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidAVP, length)
	}
	flags := uint16(length)
	if a.Mandatory {
		flags |= 0x8000
	}
	if a.Hidden {
		flags |= 0x4000
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[0:2], flags)
	binary.BigEndian.PutUint16(out[2:4], a.VendorID)
	binary.BigEndian.PutUint16(out[4:6], a.Type)
	copy(out[6:], a.Value)
	return out, nil
}

func decodeAVPs(b []byte) ([]AVP, error) {
	var out []AVP
	for len(b) != 0 {
		if len(b) < avpHeaderLen {
			return nil, ErrShortAVP
		}
		flags := binary.BigEndian.Uint16(b[:2])
		if flags&0x3c00 != 0 {
			return nil, fmt.Errorf("%w: reserved flag bits", ErrInvalidAVP)
		}
		length := int(flags & 0x03ff)
		if length < avpHeaderLen || length > len(b) {
			return nil, fmt.Errorf("%w: declared length %d, remaining %d", ErrInvalidAVP, length, len(b))
		}
		if flags&0x4000 != 0 {
			return nil, ErrHiddenAVP
		}
		out = append(out, AVP{
			Mandatory: flags&0x8000 != 0, Hidden: flags&0x4000 != 0,
			VendorID: binary.BigEndian.Uint16(b[2:4]), Type: binary.BigEndian.Uint16(b[4:6]),
			Value: append([]byte(nil), b[6:length]...),
		})
		b = b[length:]
	}
	return out, nil
}

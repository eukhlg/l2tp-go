package ppp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ProtocolIPv4 uint16 = 0x0021
	ProtocolIPCP uint16 = 0x8021
	ProtocolLCP  uint16 = 0xc021
	ProtocolPAP  uint16 = 0xc023
)

type Code uint8

const (
	ConfigureRequest Code = 1
	ConfigureAck     Code = 2
	ConfigureNak     Code = 3
	ConfigureReject  Code = 4
	TerminateRequest Code = 5
	TerminateAck     Code = 6
	EchoRequest      Code = 9
	EchoReply        Code = 10
)

var (
	ErrShortControl  = errors.New("ppp: control packet is too short")
	ErrInvalidLength = errors.New("ppp: invalid control packet length")
	ErrInvalidOption = errors.New("ppp: invalid configuration option")
)

type ControlPacket struct {
	Code       Code
	Identifier uint8
	Data       []byte
}

func DecodeControlPacket(b []byte) (ControlPacket, error) {
	if len(b) < 4 {
		return ControlPacket{}, ErrShortControl
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 4 || length != len(b) {
		return ControlPacket{}, fmt.Errorf("%w: declared %d, actual %d", ErrInvalidLength, length, len(b))
	}
	return ControlPacket{Code: Code(b[0]), Identifier: b[1], Data: append([]byte(nil), b[4:]...)}, nil
}

func (p ControlPacket) MarshalBinary() ([]byte, error) {
	length := 4 + len(p.Data)
	if length > 0xffff {
		return nil, ErrInvalidLength
	}
	out := make([]byte, length)
	out[0], out[1] = byte(p.Code), p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	copy(out[4:], p.Data)
	return out, nil
}

type Option struct {
	Type  uint8
	Value []byte
}

func DecodeOptions(b []byte) ([]Option, error) {
	var options []Option
	for len(b) != 0 {
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return nil, ErrInvalidOption
		}
		length := int(b[1])
		options = append(options, Option{Type: b[0], Value: append([]byte(nil), b[2:length]...)})
		b = b[length:]
	}
	return options, nil
}

func EncodeOptions(options ...Option) ([]byte, error) {
	var out []byte
	for _, option := range options {
		length := 2 + len(option.Value)
		if length > 255 {
			return nil, ErrInvalidOption
		}
		out = append(out, option.Type, byte(length))
		out = append(out, option.Value...)
	}
	return out, nil
}

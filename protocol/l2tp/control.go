package l2tp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MessageType identifies an L2TPv2 control message (RFC 2661 section 6.1).
type MessageType uint16

const (
	SCCRQ   MessageType = 1
	SCCRP   MessageType = 2
	SCCCN   MessageType = 3
	StopCCN MessageType = 4
	Hello   MessageType = 6
	OCRQ    MessageType = 7
	OCRP    MessageType = 8
	OCCN    MessageType = 9
	ICRQ    MessageType = 10
	ICRP    MessageType = 11
	ICCN    MessageType = 12
	CDN     MessageType = 14
	WEN     MessageType = 15
	SLI     MessageType = 16
)

// AttributeType identifies an IETF-defined AVP.
type AttributeType uint16

const (
	AttrMessageType        AttributeType = 0
	AttrResultCode         AttributeType = 1
	AttrProtocolVersion    AttributeType = 2
	AttrFramingCap         AttributeType = 3
	AttrBearerCap          AttributeType = 4
	AttrTieBreaker         AttributeType = 5
	AttrFirmwareRevision   AttributeType = 6
	AttrHostName           AttributeType = 7
	AttrVendorName         AttributeType = 8
	AttrAssignedTunnelID   AttributeType = 9
	AttrReceiveWindowSize  AttributeType = 10
	AttrChallenge          AttributeType = 11
	AttrCauseCode          AttributeType = 12
	AttrChallengeResponse  AttributeType = 13
	AttrAssignedSessionID  AttributeType = 14
	AttrCallSerialNumber   AttributeType = 15
	AttrMinimumBPS         AttributeType = 16
	AttrMaximumBPS         AttributeType = 17
	AttrBearerType         AttributeType = 18
	AttrFramingType        AttributeType = 19
	AttrCalledNumber       AttributeType = 21
	AttrCallingNumber      AttributeType = 22
	AttrSubAddress         AttributeType = 23
	AttrTxConnectSpeed     AttributeType = 24
	AttrPhysicalChannelID  AttributeType = 25
	AttrInitialReceivedLCP AttributeType = 26
	AttrLastSentLCP        AttributeType = 27
	AttrLastReceivedLCP    AttributeType = 28
	AttrProxyAuthType      AttributeType = 29
	AttrProxyAuthName      AttributeType = 30
	AttrProxyAuthChallenge AttributeType = 31
	AttrProxyAuthID        AttributeType = 32
	AttrProxyAuthResponse  AttributeType = 33
	AttrCallErrors         AttributeType = 34
	AttrACCM               AttributeType = 35
	AttrRandomVector       AttributeType = 36
	AttrPrivateGroupID     AttributeType = 37
	AttrRxConnectSpeed     AttributeType = 38
	AttrSequencingRequired AttributeType = 39
)

var (
	ErrNotControlMessage  = errors.New("l2tp: not a control message")
	ErrMissingMessageType = errors.New("l2tp: missing Message Type AVP")
	ErrInvalidAttribute   = errors.New("l2tp: invalid attribute value")
)

// ControlMessage adds typed control-message semantics to a Packet. AVPs does
// not include the Message Type AVP, which is always generated first.
type ControlMessage struct {
	Type     MessageType
	TunnelID uint16
	Ns, Nr   uint16
	AVPs     []AVP
}

func (m ControlMessage) MarshalBinary() ([]byte, error) {
	if m.Type == 0 {
		return nil, fmt.Errorf("%w: zero value", ErrMissingMessageType)
	}
	typeAVP := Uint16AVP(AttrMessageType, uint16(m.Type), true)
	avps := make([]AVP, 1, len(m.AVPs)+1)
	avps[0] = typeAVP
	for _, avp := range m.AVPs {
		if avp.VendorID == 0 && AttributeType(avp.Type) == AttrMessageType {
			return nil, fmt.Errorf("%w: duplicate Message Type AVP", ErrInvalidPacket)
		}
		avps = append(avps, avp)
	}
	return (Packet{Control: true, TunnelID: m.TunnelID, HasSequence: true, Ns: m.Ns, Nr: m.Nr, AVPs: avps}).MarshalBinary()
}

func DecodeControlMessage(b []byte) (ControlMessage, error) {
	p, err := DecodePacket(b)
	if err != nil {
		return ControlMessage{}, err
	}
	if !p.Control {
		return ControlMessage{}, ErrNotControlMessage
	}
	if len(p.AVPs) == 0 || p.AVPs[0].VendorID != 0 || AttributeType(p.AVPs[0].Type) != AttrMessageType {
		return ControlMessage{}, ErrMissingMessageType
	}
	messageType, err := p.AVPs[0].Uint16()
	if err != nil {
		return ControlMessage{}, fmt.Errorf("%w: Message Type: %v", ErrInvalidAttribute, err)
	}
	return ControlMessage{Type: MessageType(messageType), TunnelID: p.TunnelID, Ns: p.Ns, Nr: p.Nr, AVPs: append([]AVP(nil), p.AVPs[1:]...)}, nil
}

// Find returns the first unhidden IETF AVP of the requested type.
func (m ControlMessage) Find(attribute AttributeType) (AVP, bool) {
	for _, avp := range m.AVPs {
		if avp.VendorID == 0 && AttributeType(avp.Type) == attribute {
			return avp, true
		}
	}
	return AVP{}, false
}

// Uint16AVP constructs an IETF AVP containing a network-byte-order uint16.
func Uint16AVP(attribute AttributeType, value uint16, mandatory bool) AVP {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, value)
	return AVP{Mandatory: mandatory, Type: uint16(attribute), Value: b}
}

// Uint32AVP constructs an IETF AVP containing a network-byte-order uint32.
func Uint32AVP(attribute AttributeType, value uint32, mandatory bool) AVP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	return AVP{Mandatory: mandatory, Type: uint16(attribute), Value: b}
}

// StringAVP constructs an IETF AVP containing an opaque UTF-8 string.
func StringAVP(attribute AttributeType, value string, mandatory bool) AVP {
	return AVP{Mandatory: mandatory, Type: uint16(attribute), Value: []byte(value)}
}

func (a AVP) Uint16() (uint16, error) {
	if len(a.Value) != 2 {
		return 0, fmt.Errorf("%w: need 2 bytes, got %d", ErrInvalidAttribute, len(a.Value))
	}
	return binary.BigEndian.Uint16(a.Value), nil
}

func (a AVP) Uint32() (uint32, error) {
	if len(a.Value) != 4 {
		return 0, fmt.Errorf("%w: need 4 bytes, got %d", ErrInvalidAttribute, len(a.Value))
	}
	return binary.BigEndian.Uint32(a.Value), nil
}

func (a AVP) String() string { return string(a.Value) }

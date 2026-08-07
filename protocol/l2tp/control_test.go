package l2tp

import (
	"errors"
	"testing"
)

func TestControlMessageRoundTrip(t *testing.T) {
	want := ControlMessage{
		Type: SCCRQ, Ns: 12, Nr: 8,
		AVPs: []AVP{
			Uint16AVP(AttrProtocolVersion, 0x0100, true),
			StringAVP(AttrHostName, "vpn.example", true),
			Uint32AVP(AttrFramingCap, 3, true),
		},
	}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeControlMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != SCCRQ || got.Ns != 12 || got.Nr != 8 || len(got.AVPs) != 3 {
		t.Fatalf("unexpected message: %#v", got)
	}
	host, ok := got.Find(AttrHostName)
	if !ok || host.String() != "vpn.example" {
		t.Fatalf("unexpected hostname: %#v, %v", host, ok)
	}
	framing, ok := got.Find(AttrFramingCap)
	if !ok {
		t.Fatal("missing framing capabilities")
	}
	value, err := framing.Uint32()
	if err != nil || value != 3 {
		t.Fatalf("framing capabilities = %d, %v", value, err)
	}
}

func TestControlMessageUsesMessageTypeFirst(t *testing.T) {
	wire, err := (ControlMessage{Type: Hello}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AVPs) != 1 || p.AVPs[0].Type != uint16(AttrMessageType) || !p.AVPs[0].Mandatory {
		t.Fatalf("unexpected AVPs: %#v", p.AVPs)
	}
}

func TestDecodeControlMessageRejectsInvalidMessages(t *testing.T) {
	data, err := (Packet{Payload: []byte{1}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	missing, err := (Packet{Control: true, HasSequence: true, AVPs: []AVP{StringAVP(AttrHostName, "host", true)}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	badType, err := (Packet{Control: true, HasSequence: true, AVPs: []AVP{{Mandatory: true, Type: uint16(AttrMessageType), Value: []byte{1}}}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		wire   []byte
		target error
	}{
		{"data", data, ErrNotControlMessage},
		{"missing", missing, ErrMissingMessageType},
		{"bad-type", badType, ErrInvalidAttribute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeControlMessage(tc.wire)
			if !errors.Is(err, tc.target) {
				t.Fatalf("got %v, want %v", err, tc.target)
			}
		})
	}
}

func TestControlMessageRejectsDuplicateType(t *testing.T) {
	_, err := (ControlMessage{Type: SCCRP, AVPs: []AVP{Uint16AVP(AttrMessageType, uint16(SCCCN), true)}}).MarshalBinary()
	if !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTypedAVPRejectsWrongWidths(t *testing.T) {
	a := AVP{Value: []byte{1}}
	if _, err := a.Uint16(); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatal(err)
	}
	if _, err := a.Uint32(); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatal(err)
	}
}

package l2tp

import (
	"bytes"
	"errors"
	"testing"
)

func TestControlPacketRoundTrip(t *testing.T) {
	want := Packet{Control: true, TunnelID: 7, HasSequence: true, Ns: 3, Nr: 4, AVPs: []AVP{{Mandatory: true, Type: 0, Value: []byte{0, 1}}}}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Control || got.TunnelID != 7 || got.Ns != 3 || got.Nr != 4 || len(got.AVPs) != 1 || !bytes.Equal(got.AVPs[0].Value, []byte{0, 1}) {
		t.Fatalf("unexpected packet: %#v", got)
	}
}

func TestDataPacketRoundTrip(t *testing.T) {
	want := Packet{TunnelID: 1, SessionID: 2, Payload: []byte{0xff, 0x03, 0xc0, 0x21}}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Control || got.TunnelID != 1 || got.SessionID != 2 || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("unexpected packet: %#v", got)
	}
}

func TestDecodePacketRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name   string
		wire   []byte
		target error
	}{
		{"short", []byte{0}, ErrShortPacket},
		{"version", []byte{0, 3, 0, 0, 0, 0}, ErrBadVersion},
		{"control-no-sequence", []byte{0xc0, 2, 0, 8, 0, 0, 0, 0}, ErrInvalidPacket},
		{"oversize-length", []byte{0x40, 2, 0, 20, 0, 0, 0, 0}, ErrInvalidPacket},
		{"hidden-avp", []byte{0xc8, 2, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 6, 0, 0, 0, 0}, ErrHiddenAVP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodePacket(tc.wire)
			if !errors.Is(err, tc.target) {
				t.Fatalf("got %v, want %v", err, tc.target)
			}
		})
	}
}

func TestAVPRejectsOversizeValue(t *testing.T) {
	_, err := (AVP{Value: make([]byte, 1018)}).MarshalBinary()
	if !errors.Is(err, ErrInvalidAVP) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestControlPacketRejectsSessionID(t *testing.T) {
	_, err := (Packet{Control: true, HasSequence: true, SessionID: 1}).MarshalBinary()
	if !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeSequencedDataWithOffset(t *testing.T) {
	wire := []byte{
		0x0a, 0x02, // S and O, version 2
		0x00, 0x01, 0x00, 0x02, // tunnel and session
		0x00, 0x03, 0x00, 0x04, // Ns and Nr
		0x00, 0x02, 0xaa, 0xbb, // offset padding
		0x21, 0x45,
	}
	got, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasSequence || got.Ns != 3 || got.Nr != 4 || !bytes.Equal(got.Payload, []byte{0x21, 0x45}) {
		t.Fatalf("unexpected packet: %#v", got)
	}
}

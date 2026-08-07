package ppp

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := Frame{Protocol: 0xc021, Payload: []byte{1, 2, 3}}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFrame(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != want.Protocol || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestDecodeCompressedFrame(t *testing.T) {
	got, err := DecodeFrame([]byte{0x21, 0x45, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != 0x21 || !bytes.Equal(got.Payload, []byte{0x45, 0x00}) {
		t.Fatalf("unexpected frame: %#v", got)
	}
}

func TestDecodeFrameRejectsMalformedInput(t *testing.T) {
	for _, wire := range [][]byte{nil, {0xff, 0x03}, {0x00}, {0x00, 0x20}} {
		if _, err := DecodeFrame(wire); err == nil {
			t.Fatalf("DecodeFrame(%x) succeeded", wire)
		}
	}
	if _, err := DecodeFrame(nil); !errors.Is(err, ErrShortFrame) {
		t.Fatal(err)
	}
}

func TestMarshalRejectsAmbiguousProtocol(t *testing.T) {
	if _, err := (Frame{Protocol: 0x0121}).MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary succeeded")
	}
}

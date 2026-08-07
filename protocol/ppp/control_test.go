package ppp

import (
	"bytes"
	"errors"
	"testing"
)

func TestControlPacketAndOptionsRoundTrip(t *testing.T) {
	data, err := EncodeOptions(Option{Type: 1, Value: []byte{0x05, 0xdc}}, Option{Type: 7})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (ControlPacket{Code: ConfigureRequest, Identifier: 7, Data: data}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := DecodeControlPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	options, err := DecodeOptions(packet.Data)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Identifier != 7 || len(options) != 2 || !bytes.Equal(options[0].Value, []byte{0x05, 0xdc}) {
		t.Fatalf("packet=%#v options=%#v", packet, options)
	}
}

func TestControlCodecRejectsMalformedInput(t *testing.T) {
	for _, wire := range [][]byte{{1}, {1, 1, 0, 3}, {1, 1, 0, 8}} {
		if _, err := DecodeControlPacket(wire); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
	if _, err := DecodeOptions([]byte{1, 1}); !errors.Is(err, ErrInvalidOption) {
		t.Fatal(err)
	}
	if _, err := EncodeOptions(Option{Value: make([]byte, 254)}); !errors.Is(err, ErrInvalidOption) {
		t.Fatal(err)
	}
}

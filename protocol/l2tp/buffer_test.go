package l2tp

import (
	"bytes"
	"testing"
)

func TestBorrowedPacketAndCompatibility(t *testing.T) {
	wire, err := (Packet{TunnelID: 1, SessionID: 2, HasSequence: true, Ns: 3, Nr: 4, Payload: []byte{0x21, 0x45}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	owned, _ := DecodePacket(wire)
	view, err := DecodePacketView(wire)
	if err != nil {
		t.Fatal(err)
	}
	if cap(view.Payload) != len(view.Payload) {
		t.Fatal("unbounded view")
	}
	view.Payload[0] ^= 255
	if bytes.Equal(owned.Payload, view.Payload) || wire[len(wire)-2] != view.Payload[0] {
		t.Fatal("incorrect ownership")
	}
	for i := 0; i < 10; i++ {
		if _, err := DecodePacketView(wire[:i]); err == nil {
			t.Fatalf("accepted truncated header %d", i)
		}
	}
}
func FuzzDecodePacketView(f *testing.F) {
	for _, b := range [][]byte{nil, {0, 2, 0, 1, 0, 2}, {0x42, 2, 0, 8, 0, 1, 0, 2}, {0x0a, 2, 0, 1, 0, 2, 0, 0, 0, 0, 255, 255}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := DecodePacketView(b)
		q, e2 := DecodePacket(b)
		if (e == nil) != (e2 == nil) {
			t.Fatal("error mismatch")
		}
		if e == nil && (!bytes.Equal(p.Payload, q.Payload) || cap(p.Payload) != len(p.Payload)) {
			t.Fatal("view mismatch")
		}
	})
}

package ppp

import (
	"bytes"
	"testing"
)

func TestBorrowedFrameAndCompatibility(t *testing.T) {
	for _, wire := range [][]byte{{0xff, 3, 0, 0x21, 0x45, 1}, {0, 0x21, 0x45, 1}, {0x21, 0x45, 1}} {
		owned, err := DecodeFrame(wire)
		if err != nil {
			t.Fatal(err)
		}
		view, err := DecodeFrameView(wire)
		if err != nil {
			t.Fatal(err)
		}
		if cap(view.Payload) != len(view.Payload) {
			t.Fatal("unbounded view")
		}
		view.Payload[0] ^= 255
		if bytes.Equal(owned.Payload, view.Payload) {
			t.Fatal("legacy API aliases input")
		}
		if wire[len(wire)-2] != view.Payload[0] {
			t.Fatal("borrowed API copied")
		}
	}
}
func FuzzDecodeFrameView(f *testing.F) {
	for _, b := range [][]byte{nil, {0x21, 0x45}, {0xff, 3, 0, 0x21}, {0, 0}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := DecodeFrameView(b)
		q, e2 := DecodeFrame(b)
		if (e == nil) != (e2 == nil) {
			t.Fatal("error mismatch")
		}
		if e == nil && (p.Protocol != q.Protocol || !bytes.Equal(p.Payload, q.Payload) || cap(p.Payload) != len(p.Payload)) {
			t.Fatal("view mismatch")
		}
	})
}

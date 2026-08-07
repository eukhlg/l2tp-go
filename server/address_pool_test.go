package server

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAddressPoolAcquireRelease(t *testing.T) {
	pool, err := NewAddressPool(netip.MustParsePrefix("10.0.0.0/24"), netip.MustParseAddr("10.0.0.100"), netip.MustParseAddr("10.0.0.101"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := pool.Acquire()
	b, _ := pool.Acquire()
	if a.String() != "10.0.0.100" || b.String() != "10.0.0.101" || pool.InUse() != 2 {
		t.Fatalf("a=%s b=%s used=%d", a, b, pool.InUse())
	}
	if _, err := pool.Acquire(); !errors.Is(err, ErrAddressPoolExhausted) {
		t.Fatalf("error=%v", err)
	}
	pool.Release(a)
	c, err := pool.Acquire()
	if err != nil || c != a {
		t.Fatalf("c=%s err=%v", c, err)
	}
}

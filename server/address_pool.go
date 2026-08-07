package server

import (
	"errors"
	"net/netip"
	"sync"
)

var ErrAddressPoolExhausted = errors.New("l2tp server: client address pool exhausted")

// AddressPool leases a bounded inclusive range of IPv4 addresses.
type AddressPool struct {
	mu     sync.Mutex
	start  uint32
	end    uint32
	leases map[uint32]struct{}
}

func NewAddressPool(prefix netip.Prefix, start, end netip.Addr) (*AddressPool, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || !start.Is4() || !end.Is4() || !prefix.Contains(start) || !prefix.Contains(end) {
		return nil, errors.New("l2tp server: address pool must be inside an IPv4 prefix")
	}
	s, e := addrUint32(start), addrUint32(end)
	if s > e || s == addrUint32(prefix.Addr()) || (prefix.Bits() <= 30 && e == broadcastUint32(prefix)) {
		return nil, errors.New("l2tp server: invalid client address pool range")
	}
	return &AddressPool{start: s, end: e, leases: make(map[uint32]struct{})}, nil
}

func (p *AddressPool) Acquire() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for value := p.start; ; value++ {
		if _, used := p.leases[value]; !used {
			p.leases[value] = struct{}{}
			return uint32Addr(value), nil
		}
		if value == p.end {
			break
		}
	}
	return netip.Addr{}, ErrAddressPoolExhausted
}

func (p *AddressPool) Release(address netip.Addr) {
	if !address.Is4() {
		return
	}
	p.mu.Lock()
	delete(p.leases, addrUint32(address))
	p.mu.Unlock()
}

func (p *AddressPool) InUse() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.leases) }

func addrUint32(address netip.Addr) uint32 {
	b := address.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32Addr(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func broadcastUint32(prefix netip.Prefix) uint32 {
	mask := uint32(0xffffffff) << (32 - prefix.Bits())
	return addrUint32(prefix.Masked().Addr()) | ^mask
}

package server

import (
	"unsafe"

	"github.com/eukhlg/netio/packetbuf"
)

// ownedView narrows buffer's view to exactly ipv4, which must lie in the view
// once the buffer's headroom is restored, so an owned router finds the packet
// as buffer.Bytes() and its free headroom as buffer.Headroom(). No bytes move.
// It reports false, leaving only the headroom restored, if ipv4 lies elsewhere.
func ownedView(buffer *packetbuf.Buffer, ipv4 []byte) bool {
	if len(ipv4) == 0 {
		return false
	}
	if _, err := buffer.Prepend(buffer.Headroom()); err != nil {
		return false
	}
	view := buffer.Bytes()
	base, start := uintptr(unsafe.Pointer(unsafe.SliceData(view))), uintptr(unsafe.Pointer(unsafe.SliceData(ipv4)))
	if start < base || start-base > uintptr(len(view)) {
		return false
	}
	offset := int(start - base)
	if len(ipv4) > len(view)-offset {
		return false
	}
	return buffer.TrimFront(offset) == nil && buffer.Truncate(len(ipv4)) == nil
}

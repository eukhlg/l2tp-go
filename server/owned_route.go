package server

import (
	"context"
	"unsafe"
)

type packetStorageKey struct{}

// WithPacketStorage supplies storage retained by the delivery driver through
// its flush hook. It does not transfer ownership to callbacks.
func WithPacketStorage(ctx context.Context, storage []byte) context.Context {
	return context.WithValue(ctx, packetStorageKey{}, storage)
}
func packetStorage(ctx context.Context, frame []byte) ([]byte, int, bool) {
	storage, ok := ctx.Value(packetStorageKey{}).([]byte)
	if !ok || len(storage) == 0 || len(frame) == 0 {
		return nil, 0, false
	}
	base, start := uintptr(unsafe.Pointer(unsafe.SliceData(storage))), uintptr(unsafe.Pointer(unsafe.SliceData(frame)))
	if start < base || start-base > uintptr(len(storage)) {
		return nil, 0, false
	}
	offset := int(start - base)
	if len(frame) > len(storage)-offset {
		return nil, 0, false
	}
	return storage, offset, true
}

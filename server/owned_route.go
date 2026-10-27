package server

import (
	"context"
	"unsafe"
)

type packetStorageKey struct{}
type packetStorageSlotKey struct{}

// packetStorageSlot carries the current packet's storage through a context
// created once per driver, so per-packet dispatch allocates no context.
type packetStorageSlot struct{ storage []byte }

// WithPacketStorage supplies storage retained by the delivery driver through
// its flush hook. It does not transfer ownership to callbacks.
func WithPacketStorage(ctx context.Context, storage []byte) context.Context {
	return context.WithValue(ctx, packetStorageKey{}, storage)
}

// WithPacketStorageSlot returns a context whose packet storage is set per
// packet with SetPacketStorage, for drivers that dispatch from one goroutine.
func WithPacketStorageSlot(ctx context.Context) context.Context {
	return context.WithValue(ctx, packetStorageSlotKey{}, &packetStorageSlot{})
}

// SetPacketStorage sets the current packet's storage in a context created by
// WithPacketStorageSlot (nil clears it). It reports false if ctx has no slot.
func SetPacketStorage(ctx context.Context, storage []byte) bool {
	slot, ok := ctx.Value(packetStorageSlotKey{}).(*packetStorageSlot)
	if ok {
		slot.storage = storage
	}
	return ok
}

func packetStorage(ctx context.Context, frame []byte) ([]byte, int, bool) {
	storage, ok := ctx.Value(packetStorageKey{}).([]byte)
	if !ok {
		slot, hasSlot := ctx.Value(packetStorageSlotKey{}).(*packetStorageSlot)
		if !hasSlot {
			return nil, 0, false
		}
		storage = slot.storage
	}
	if len(storage) == 0 || len(frame) == 0 {
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

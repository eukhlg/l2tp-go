package server

import (
	"context"
	"errors"
	"net"
)

// readBatch is an exclusive ownership envelope. It may be transferred only as
// a whole, and released only after all consumers (including route flush) finish.
type readBatch struct {
	messages []ReceivedDatagram
	buffers  []ReceiveBuffer
}

func (s *Server) acquireReadBatch(size, headroom int) (*readBatch, error) {
	b := &readBatch{messages: make([]ReceivedDatagram, size), buffers: make([]ReceiveBuffer, 0, size)}
	for i := range b.messages {
		var buffer ReceiveBuffer
		if allocator, ok := s.Conn.(ReceiveBufferAllocator); ok {
			var err error
			buffer, err = allocator.AcquireReceiveBuffer()
			if err != nil {
				b.release()
				return nil, err
			}
		} else {
			buffer = heapReceiveBuffer(make([]byte, 65535+headroom))
		}
		b.buffers = append(b.buffers, buffer)
		storage := buffer.Bytes()
		if len(storage) <= headroom {
			b.release()
			return nil, errors.New("l2tp server: receive buffer smaller than headroom")
		}
		b.messages[i].Payload = storage[headroom:]
	}
	return b, nil
}

func (b *readBatch) release() {
	for _, buffer := range b.buffers {
		buffer.Release()
	}
	clear(b.buffers)
	b.buffers = nil
	clear(b.messages)
}

func (b *readBatch) read(conn net.PacketConn, batch BatchPacketConn, batched bool) (int, error) {
	if batched {
		return batch.ReadBatch(b.messages)
	}
	m := &b.messages[0]
	var err error
	m.N, m.Peer, err = conn.ReadFrom(m.Payload)
	m.Truncated = m.N == len(m.Payload)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (s *Server) processReadBatch(ctx context.Context, b *readBatch, count int) error {
	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		m := &b.messages[i]
		if !m.Truncated && m.N >= 0 && m.N <= len(m.Payload) && m.Peer != nil {
			if err := s.processDatagram(WithPacketStorage(ctx, b.buffers[i].Bytes()), m.Peer, m.Payload[:m.N:m.N]); err != nil {
				return err
			}
		}
	}
	return nil
}

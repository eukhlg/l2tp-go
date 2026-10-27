package server

import (
	"context"
	"errors"
	"net"
)

// readBatch is an exclusive ownership envelope. It may be transferred only as
// a whole, and recycled only after all consumers (including route flush)
// finish. Envelopes and their buffers are reused for the life of Serve, so a
// read costs no allocation and recycling clears only the bytes received.
type readBatch struct {
	messages []ReceivedDatagram
	buffers  []ReceiveBuffer
	headroom int
	count    int
	// ctx carries this envelope's route batch and packet-storage slot; flush
	// writes the route batch. Both are created once per envelope.
	ctx     context.Context
	flush   func() error
	storage *packetStorageSlot
}

// readBatchPool bounds receive storage: at most max envelopes exist, and
// acquire blocks until one is recycled.
type readBatchPool struct {
	s        *Server
	ctx      context.Context
	size     int
	headroom int
	max      int
	created  int
	all      []*readBatch
	free     chan *readBatch
}

func (s *Server) newReadBatchPool(ctx context.Context, size, headroom, max int) *readBatchPool {
	return &readBatchPool{s: s, ctx: ctx, size: size, headroom: headroom, max: max, free: make(chan *readBatch, max)}
}

// acquire must be called from one goroutine at a time (the receive stage).
func (p *readBatchPool) acquire() (*readBatch, error) {
	select {
	case b := <-p.free:
		return b, nil
	default:
	}
	if p.created < p.max {
		b, err := p.newBatch()
		if err != nil {
			return nil, err
		}
		p.created++
		p.all = append(p.all, b)
		return b, nil
	}
	select {
	case b := <-p.free:
		return b, nil
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
}

func (p *readBatchPool) newBatch() (*readBatch, error) {
	b := &readBatch{messages: make([]ReceivedDatagram, p.size), buffers: make([]ReceiveBuffer, 0, p.size), headroom: p.headroom}
	for i := range b.messages {
		var buffer ReceiveBuffer
		if allocator, ok := p.s.Conn.(ReceiveBufferAllocator); ok {
			var err error
			buffer, err = allocator.AcquireReceiveBuffer()
			if err != nil {
				b.release()
				return nil, err
			}
		} else {
			buffer = heapReceiveBuffer(make([]byte, 65535+p.headroom))
		}
		b.buffers = append(b.buffers, buffer)
		storage := buffer.Bytes()
		if len(storage) <= p.headroom {
			b.release()
			return nil, errors.New("l2tp server: receive buffer smaller than headroom")
		}
		b.messages[i].Payload = storage[p.headroom:]
	}
	b.storage = &packetStorageSlot{}
	b.ctx, b.flush = p.ctx, func() error { return nil }
	if p.s.NewRouteBatch != nil {
		b.ctx, b.flush = p.s.NewRouteBatch(p.ctx)
	}
	b.ctx = context.WithValue(b.ctx, packetStorageSlotKey{}, b.storage)
	return b, nil
}

// recycle clears the received bytes and the headroom (a TUN virtio header may
// have been written there; GRO growth is scrubbed by the router) and makes the
// envelope available again. Called once per acquire, after flush.
func (p *readBatchPool) recycle(b *readBatch) {
	for i := 0; i < b.count && i < len(b.messages); i++ {
		m := &b.messages[i]
		storage := b.buffers[i].Bytes()
		clear(storage[:b.headroom])
		clear(m.Payload[:min(max(m.N, 0), len(m.Payload))])
		m.N, m.Peer, m.Truncated = 0, nil, false
	}
	b.count = 0
	b.storage.storage = nil
	p.free <- b
}

// close releases every envelope's buffers. All envelopes must have been
// recycled or abandoned by their stages.
func (p *readBatchPool) close() {
	for _, b := range p.all {
		b.release()
	}
	p.all = nil
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
		n, err := batch.ReadBatch(b.messages)
		if n > 0 && n <= len(b.messages) {
			b.count = n
		}
		return n, err
	}
	m := &b.messages[0]
	var err error
	m.N, m.Peer, err = conn.ReadFrom(m.Payload)
	m.Truncated = m.N == len(m.Payload)
	if err != nil {
		return 0, err
	}
	b.count = 1
	return 1, nil
}

func (s *Server) processReadBatch(b *readBatch, count int) error {
	for i := 0; i < count; i++ {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		m := &b.messages[i]
		if !m.Truncated && m.N >= 0 && m.N <= len(m.Payload) && m.Peer != nil {
			b.storage.storage = b.buffers[i].Bytes()
			if err := s.processDatagram(b.ctx, m.Peer, m.Payload[:m.N:m.N]); err != nil {
				b.storage.storage = nil
				return err
			}
		}
	}
	b.storage.storage = nil
	return nil
}

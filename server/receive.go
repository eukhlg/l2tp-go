package server

import (
	"context"
	"errors"
	"net"

	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

// readBatch is an exclusive ownership envelope. It may be transferred only as
// a whole, and recycled only after all consumers (including route flush)
// finish. Envelopes and their netio buffers are reused for the life of Serve,
// so a read costs no allocation and recycling clears only the bytes received
// and each buffer's headroom.
type readBatch struct {
	messages []udptransport.Message
	buffers  []*packetbuf.Buffer
	// heads are the buffers' headrooms, where an owned router may write a
	// header (for example a TUN virtio header) in front of a packet.
	heads [][]byte
	count int
	// ctx carries this envelope's route batch; flush writes it. Both are
	// created once per envelope.
	ctx   context.Context
	flush func() error
}

// readBatchPool bounds receive storage: at most max envelopes exist, and
// acquire blocks until one is recycled.
type readBatchPool struct {
	s       *Server
	ctx     context.Context
	size    int
	max     int
	created int
	all     []*readBatch
	free    chan *readBatch
}

func (s *Server) newReadBatchPool(ctx context.Context, size, max int) *readBatchPool {
	return &readBatchPool{s: s, ctx: ctx, size: size, max: max, free: make(chan *readBatch, max)}
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
	b := &readBatch{messages: make([]udptransport.Message, p.size), buffers: make([]*packetbuf.Buffer, 0, p.size), heads: make([][]byte, 0, p.size)}
	for i := range b.messages {
		buffer, err := p.s.acquireBuffer(packetbuf.MaxPacket)
		if err != nil {
			b.release(p.s.releaseBuffer)
			return nil, err
		}
		b.buffers = append(b.buffers, buffer)
		head, err := buffer.Prepend(buffer.Headroom())
		if err == nil {
			err = buffer.TrimFront(len(head))
		}
		if err != nil || len(head) == 0 {
			b.release(p.s.releaseBuffer)
			return nil, errors.New("l2tp server: receive buffer without headroom")
		}
		b.heads = append(b.heads, head)
		b.messages[i].Payload = buffer.Bytes()
	}
	b.ctx, b.flush = p.ctx, func() error { return nil }
	if p.s.NewRouteBatch != nil {
		b.ctx, b.flush = p.s.NewRouteBatch(p.ctx)
	}
	return b, nil
}

// recycle clears the received bytes and the headroom (a TUN virtio header may
// have been written there; GRO growth is scrubbed by the router), restores
// each buffer's view after an owned router moved it, and makes the envelope
// available again. Called once per acquire, after flush.
func (p *readBatchPool) recycle(b *readBatch) {
	for i := 0; i < b.count && i < len(b.messages); i++ {
		m := &b.messages[i]
		clear(b.heads[i])
		clear(m.Payload[:min(max(m.N, 0), len(m.Payload))])
		m.N, m.Peer, m.Truncated = 0, nil, false
		restoreView(b.buffers[i], len(b.heads[i]), len(m.Payload))
	}
	b.count = 0
	p.free <- b
}

// restoreView sets buffer's view back to its receive payload: head bytes of
// headroom, then size bytes.
func restoreView(buffer *packetbuf.Buffer, head, size int) {
	_, _ = buffer.Prepend(buffer.Headroom())
	_ = buffer.TrimFront(head)
	if n := size - buffer.Len(); n > 0 {
		_, _ = buffer.Append(n)
	}
}

// close releases every envelope's buffers. All envelopes must have been
// recycled or abandoned by their stages.
func (p *readBatchPool) close() {
	for _, b := range p.all {
		b.release(p.s.releaseBuffer)
	}
	p.all = nil
}

func (b *readBatch) release(release func(*packetbuf.Buffer)) {
	for _, buffer := range b.buffers {
		release(buffer)
	}
	clear(b.buffers)
	b.buffers = nil
	clear(b.heads)
	b.heads = nil
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
			if err := s.processDatagram(b.ctx, m.Peer, m.Payload[:m.N:m.N], b.buffers[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

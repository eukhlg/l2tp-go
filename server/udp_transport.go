package server

import (
	"context"
	"errors"
	"net"

	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

// Compile-time checks: Serve discovers these optional capabilities by type
// assertion, so a signature drift would otherwise silently disable batching.
var (
	_ BatchPacketConn       = (*UDPTransport)(nil)
	_ OwnedPacketWriter     = (*UDPTransport)(nil)
	_ SessionDatagramWriter = (*UDPTransport)(nil)
	_ FlowPacketWriter      = (*UDPTransport)(nil)
)

// UDPTransport is the plain L2TP socket on netio: batched receive into the
// server's pooled buffers and a sharded owned sender. Serve uses it through
// BatchPacketConn and the owned writer interfaces.
type UDPTransport struct {
	net.PacketConn
	receiver    *udptransport.Conn
	sender      *udptransport.ShardedSender
	descriptors int
}

// NewUDPTransport receives in batches of size and sends through shards
// independent sender goroutines on the same socket. The first shard shares the receiver's descriptor and Conn (separate
// rx/tx state); each further shard writes through its own duplicate descriptor
// with its own batch writer, because Go serializes writes per descriptor.
// Where duplication is unavailable a shard shares conn and still works, but
// serialized. Flow-keyed writes keep each inner flow on one shard; control and
// unkeyed writes use flow key 0.
func NewUDPTransport(conn net.PacketConn, size, shards int, options udptransport.Options) (*UDPTransport, error) {
	if shards < 1 {
		return nil, errors.New("l2tp server: at least one send shard required")
	}
	udp, err := udptransport.NewWithOptions(conn, size, options)
	if err != nil {
		return nil, err
	}
	list := []udptransport.Shard{{Conn: conn, Writer: udp}}
	descriptors := 1
	fail := func(err error) (*UDPTransport, error) {
		for _, shard := range list[1:] {
			if shard.Conn != conn {
				shard.Conn.Close()
			}
		}
		return nil, err
	}
	for len(list) < shards {
		shardConn := conn
		if duplicate, err := udptransport.DuplicatePacketConn(conn); err == nil {
			shardConn = duplicate
			descriptors++
		}
		writer, err := udptransport.NewWithOptions(shardConn, size, options)
		if err != nil {
			if shardConn != conn {
				shardConn.Close()
			}
			return fail(err)
		}
		list = append(list, udptransport.Shard{Conn: shardConn, Writer: writer})
	}
	// Serve owns cancellation/deadlines so StopCCN can be sent before Close.
	sender, err := udptransport.NewShardedSender(context.Background(), list, udptransport.SenderQueueCapacity, size)
	if err != nil {
		return fail(err)
	}
	return &UDPTransport{PacketConn: conn, receiver: udp, sender: sender, descriptors: descriptors}, nil
}

// SendDescriptors reports how many distinct socket descriptors the shards use.
func (t *UDPTransport) SendDescriptors() int { return t.descriptors }

// SendShards reports the number of sender goroutines.
func (t *UDPTransport) SendShards() int { return t.sender.Shards() }

func (t *UDPTransport) BatchSize() int { return t.receiver.BatchSize() }

// ReadBatch reads into the caller's messages directly.
func (t *UDPTransport) ReadBatch(messages []udptransport.Message) (int, error) {
	n, err := t.receiver.Read(messages)
	if err != nil {
		if failure := t.sender.Err(); failure != nil && !errors.Is(failure, context.Canceled) {
			return n, failure
		}
	}
	return n, err
}

// WriteTo is an ordered synchronous control/retransmission write: its barrier
// waits for actual socket completion, rather than reporting queue acceptance.
func (t *UDPTransport) WriteTo(payload []byte, peer net.Addr) (int, error) {
	if err := t.WriteSessionPacket(payload, peer, nil); err != nil {
		return 0, err
	}
	if err := t.Flush(context.Background()); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// WritePacket always consumes the buffer, including after failed acceptance.
func (t *UDPTransport) WritePacket(buffer *packetbuf.Buffer, peer net.Addr, eligible func() bool) error {
	return t.WriteFlowPacket(buffer, peer, eligible, 0)
}

// WriteFlowPacket is WritePacket on the shard selected by flow. It always
// consumes the buffer; accepted buffers are released by that shard's sender.
func (t *UDPTransport) WriteFlowPacket(buffer *packetbuf.Buffer, peer net.Addr, eligible func() bool, flow uint32) error {
	err := t.sender.Enqueue(context.Background(), udptransport.Datagram{Payload: buffer.Bytes(), Peer: peer, Owner: buffer, Eligible: eligible, Flow: flow})
	if err != nil {
		buffer.Release()
	}
	if errors.Is(err, udptransport.ErrIneligible) {
		return ErrSessionNotEstablished
	}
	return err
}
func (t *UDPTransport) WriteSessionPacket(payload []byte, peer net.Addr, eligible func() bool) error {
	buffer, err := packetbuf.Copy(payload)
	if err != nil {
		return err
	}
	return t.WritePacket(buffer, peer, eligible)
}
func (t *UDPTransport) Flush(ctx context.Context) error { return t.sender.Flush(ctx) }

// Close stops the sender, which also closes the socket. Queued datagrams are
// discarded; callers needing delivery must Flush first. A prior write failure
// is reported, while the cancellation caused by Close itself is not.
func (t *UDPTransport) Close() error {
	t.sender.Close()
	if err := t.sender.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (t *UDPTransport) GSOEnabled() bool { return t.receiver.GSOEnabled() }

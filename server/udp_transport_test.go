package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

func TestUDPTransportMixedDestinationsAndTransfer(t *testing.T) {
	for _, batchSize := range []int{1, 32, 128} {
		t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
			a, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			transport, err := NewUDPTransport(socket, batchSize, 1, udptransport.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			var views [][]byte
			for i := 0; i < 8; i++ {
				buffer, _ := packetbuf.Copy([]byte{byte(i), 42})
				views = append(views, buffer.Bytes())
				peer := a.LocalAddr()
				if i%2 != 0 {
					peer = b.LocalAddr()
				}
				if err := transport.WritePacket(buffer, peer, nil); err != nil {
					t.Fatal(err)
				}
			}
			if err := transport.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, v := range views {
				if !bytes.Equal(v, make([]byte, len(v))) {
					t.Fatal("completed buffer was not erased")
				}
			}
			for parity, c := range []net.PacketConn{a, b} {
				c.SetReadDeadline(time.Now().Add(time.Second))
				for i := parity; i < 8; i += 2 {
					buf := make([]byte, 10)
					n, peer, err := c.ReadFrom(buf)
					if err != nil || n != 2 || buf[0] != byte(i) || peer.String() != socket.LocalAddr().String() {
						t.Fatalf("n=%d peer=%v err=%v", n, peer, err)
					}
				}
			}
			// Control writes are barriers and pass through the same destination-preserving FIFO.
			if _, err := transport.WriteTo([]byte{99}, a.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 10)
			if _, _, err := a.ReadFrom(buf); err != nil || buf[0] != 99 {
				t.Fatal(err)
			}
			transport.Close()
			buffer, _ := packetbuf.Copy([]byte{123})
			view := buffer.Bytes()
			if err := transport.WritePacket(buffer, a.LocalAddr(), nil); err == nil {
				t.Fatal("accepted after close")
			}
			if view[0] != 0 {
				t.Fatal("rejected owned buffer not released")
			}
		})
	}
}
func TestUDPTransportReceiveBorrowedSlotsAndTruncation(t *testing.T) {
	for _, batchSize := range []int{1, 32, 128} {
		t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			transport, _ := NewUDPTransport(socket, batchSize, 1, udptransport.Options{})
			defer transport.Close()
			tx, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Close()
			for i := 0; i < 3; i++ {
				tx.WriteTo([]byte{byte(i), 42}, socket.LocalAddr())
			}
			slots := make([]udptransport.Message, transport.BatchSize())
			for i := range slots {
				slots[i].Payload = make([]byte, 10)
			}
			socket.SetReadDeadline(time.Now().Add(time.Second))
			next := 0
			for next < 3 {
				n, err := transport.ReadBatch(slots)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < n; i++ {
					if slots[i].N != 2 || slots[i].Truncated || slots[i].Payload[0] != byte(next) {
						t.Fatal("invalid returned slot")
					}
					next++
				}
			}
			tx.WriteTo(make([]byte, 50), socket.LocalAddr())
			n, err := transport.ReadBatch(slots)
			if err != nil || n != 1 || !slots[0].Truncated {
				t.Fatalf("truncation n=%d err=%v", n, err)
			}
			transport.Close()
			if _, err := transport.ReadBatch(slots); !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func TestUDPTransportSenderFailureWakesReceiverAndReleases(t *testing.T) {
	for _, batchSize := range []int{1, 32, 128} {
		t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			transport, _ := NewUDPTransport(socket, batchSize, 1, udptransport.Options{})
			defer transport.Close()
			buffer, _ := packetbuf.Copy([]byte{123})
			view := buffer.Bytes()
			err = transport.WritePacket(buffer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: -1}, nil)
			if err != nil {
				t.Fatal(err)
			}
			socket.SetReadDeadline(time.Now().Add(time.Second))
			_, err = transport.ReadBatch([]udptransport.Message{{Payload: make([]byte, 100)}})
			if err == nil {
				t.Fatal("asynchronous sender error not surfaced")
			}
			transport.Close()
			if view[0] != 0 {
				t.Fatal("failed send leaked accepted buffer")
			}
		})
	}
}

func TestUDPTransportControlHandshakeAndGracefulStop(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(fmt.Sprintf("pipeline=%t", pipeline), func(t *testing.T) {
			for _, batchSize := range []int{1, 32, 128} {
				t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
					socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					transport, _ := NewUDPTransport(socket, batchSize, 1, udptransport.Options{})
					defer transport.Close()
					s, _ := New(transport, Config{HostName: "server", FirstTunnelID: 10})
					s.BorrowedReceive = true
					s.ReceivePipeline = pipeline
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					done := make(chan error, 1)
					go func() { done <- s.Serve(ctx) }()
					client, err := net.DialUDP("udp4", nil, socket.LocalAddr().(*net.UDPAddr))
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					channel := l2tp.NewControlChannel(0, 1)
					wire, _ := channel.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 1, true), l2tp.StringAVP(l2tp.AttrHostName, "client", true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 20, true)}}, time.Now())
					if _, err := client.Write(wire); err != nil {
						t.Fatal(err)
					}
					client.SetReadDeadline(time.Now().Add(2 * time.Second))
					buf := make([]byte, 2048)
					n, err := client.Read(buf)
					if err != nil {
						t.Fatal(err)
					}
					message, err := channel.Receive(buf[:n])
					if err != nil || message == nil || message.Type != l2tp.SCCRP {
						t.Fatalf("reply=%v err=%v", message, err)
					}
					cancel()
					n, err = client.Read(buf)
					if err != nil {
						t.Fatal(err)
					}
					message, err = channel.Receive(buf[:n])
					if err != nil || message == nil || message.Type != l2tp.StopCCN {
						t.Fatalf("stop=%v err=%v", message, err)
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("cancelled server stuck")
					}
				})
			}
		})
	}
}

func TestShardedTransportKeepsFlowsInOrderOverRealSocket(t *testing.T) {
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewUDPTransport(socket, 32, 3, udptransport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if transport.SendShards() != 3 || transport.SendDescriptors() != 3 {
		t.Fatalf("shards = %d descriptors = %d", transport.SendShards(), transport.SendDescriptors())
	}
	const flows, perFlow = 6, 40
	for i := 0; i < perFlow; i++ {
		for f := 0; f < flows; f++ {
			buffer, _ := packetbuf.Copy([]byte{byte(f), byte(i)})
			if err := transport.WriteFlowPacket(buffer, receiver.LocalAddr(), nil, uint32(f)*0x9e3779b9); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := transport.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := make([]int, flows)
	receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	for n := 0; n < flows*perFlow; n++ {
		buf := make([]byte, 4)
		_, from, err := receiver.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if from.String() != socket.LocalAddr().String() {
			t.Fatalf("datagram from %v, want the transport's address %v", from, socket.LocalAddr())
		}
		f := int(buf[0])
		if int(buf[1]) != next[f] {
			t.Fatalf("flow %d: got %d, want %d", f, buf[1], next[f])
		}
		next[f]++
	}
	if _, err := NewUDPTransport(socket, 32, 0, udptransport.Options{}); err == nil {
		t.Fatal("zero shards accepted")
	}
}

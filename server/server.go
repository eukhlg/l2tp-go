package server

import (
	"context"
	"errors"
	"net"
	"time"
)

type DataHandler func(context.Context, DataFrame) error

type Server struct {
	Conn              net.PacketConn
	Engine            *Engine
	HandleData        DataHandler
	RetransmitTimeout time.Duration
	MaxRetries        int
}

// Listen creates an L2TP UDP listener. Standard L2TP uses address ":1701".
func Listen(address string, config Config) (*Server, error) {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	return &Server{Conn: conn, Engine: NewEngine(config), RetransmitTimeout: time.Second, MaxRetries: 5}, nil
}

// Serve runs until the context is cancelled, the connection is closed, or a
// data handler returns an error. The caller remains responsible for Close.
func (s *Server) Serve(ctx context.Context) error {
	if s.Conn == nil || s.Engine == nil {
		return errors.New("l2tp server: Conn and Engine are required")
	}
	tick := s.RetransmitTimeout / 2
	if tick <= 0 {
		tick = 500 * time.Millisecond
	}
	buffer := make([]byte, 65535)
	for {
		if err := s.Conn.SetReadDeadline(time.Now().Add(tick)); err != nil {
			return err
		}
		n, peer, err := s.Conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				return err
			}
		} else {
			result, handleErr := s.Engine.HandleDatagram(peer, buffer[:n], time.Now())
			if handleErr != nil {
				continue
			} // A malformed peer must not stop the listener.
			for _, reply := range result.Replies {
				if _, err := s.Conn.WriteTo(reply, peer); err != nil {
					return err
				}
			}
			if result.Data != nil && s.HandleData != nil {
				if err := s.HandleData(ctx, *result.Data); err != nil {
					return err
				}
			}
		}
		packets, err := s.Engine.Retransmit(time.Now(), s.RetransmitTimeout, s.MaxRetries)
		if err != nil {
			return err
		}
		for _, packet := range packets {
			if _, err := s.Conn.WriteTo(packet.Payload, packet.Peer); err != nil {
				return err
			}
		}
	}
}

func (s *Server) Close() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}

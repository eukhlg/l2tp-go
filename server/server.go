package server

import (
	"context"
	"errors"
	"net"
	"time"
)

type DataHandler func(context.Context, DataFrame) error

// IPv4Router accepts a packet from a client. The send callback may be used
// synchronously to route zero or more return packets to that same PPP session.
type IPv4Router func(context.Context, DataFrame, func([]byte) error) error
type SessionOpenHandler func(context.Context, SessionInfo, func([]byte) error) error
type SessionCloseHandler func(context.Context, SessionInfo)

type Server struct {
	Conn              net.PacketConn
	Engine            *Engine
	HandleData        DataHandler
	RouteIPv4         IPv4Router
	SessionOpened     SessionOpenHandler
	SessionClosed     SessionCloseHandler
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
				s.Engine.debugf("datagram rejected peer=%s error=%v", peer, handleErr)
				continue
			} // A malformed peer must not stop the listener.
			for _, reply := range result.Replies {
				if _, err := s.Conn.WriteTo(reply, peer); err != nil {
					return err
				}
				s.Engine.debugf("udp tx peer=%s bytes=%d", peer, len(reply))
			}
			if result.Opened != nil && s.SessionOpened != nil {
				info := *result.Opened
				send := func(payload []byte) error {
					packet, err := s.Engine.SendIPv4(info.TunnelID, info.SessionID, payload)
					if err != nil {
						return err
					}
					_, err = s.Conn.WriteTo(packet.Payload, packet.Peer)
					return err
				}
				if err := s.SessionOpened(ctx, info, send); err != nil {
					return err
				}
			}
			if s.SessionClosed != nil {
				for _, info := range result.Closed {
					s.SessionClosed(ctx, info)
				}
			}
			if result.Data != nil && s.HandleData != nil {
				if err := s.HandleData(ctx, *result.Data); err != nil {
					return err
				}
			}
			if result.Data != nil && result.Data.IPv4 != nil && s.RouteIPv4 != nil {
				frame := *result.Data
				send := func(payload []byte) error {
					packet, err := s.Engine.SendIPv4(frame.TunnelID, frame.Session.LocalID, payload)
					if err != nil {
						return err
					}
					_, err = s.Conn.WriteTo(packet.Payload, packet.Peer)
					return err
				}
				if err := s.RouteIPv4(ctx, frame, send); err != nil {
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

// Package server provides an embeddable L2TPv2/PPP server and optional
// IKEv1/ESP transports.
//
// The package does not require a TUN device or modify host networking. An
// embedding application can inject net.PacketConn transports with New,
// NewIKEServer, NewNATTServer, and NewRawESPServer, then consume authenticated
// session lifecycle events and raw IPv4 packets through Server callbacks.
// The cmd/l2tp-go frontend is one consumer; a sing-box endpoint can be another.
package server

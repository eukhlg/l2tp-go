package l2tp

import (
	"errors"
	"fmt"
)

type TunnelState uint8

func (s TunnelState) String() string {
	if int(s) < len(tunnelStateNames) {
		return tunnelStateNames[s]
	}
	return fmt.Sprintf("TunnelState(%d)", s)
}

var tunnelStateNames = [...]string{"idle", "wait-connect", "established", "closed"}

const (
	TunnelIdle TunnelState = iota
	TunnelWaitConnect
	TunnelEstablished
	TunnelClosed
)

type SessionState uint8

func (s SessionState) String() string {
	if int(s) < len(sessionStateNames) {
		return sessionStateNames[s]
	}
	return fmt.Sprintf("SessionState(%d)", s)
}

var sessionStateNames = [...]string{"wait-connect", "established"}

const (
	SessionWaitConnect SessionState = iota
	SessionEstablished
)

var (
	ErrUnexpectedMessage = errors.New("l2tp: unexpected control message")
	ErrMissingAttribute  = errors.New("l2tp: required attribute is missing")
	ErrUnknownSession    = errors.New("l2tp: unknown session")
)

type Session struct {
	LocalID, PeerID uint16
	State           SessionState
}

type ServerTunnelConfig struct {
	LocalTunnelID  uint16
	FirstSessionID uint16
	HostName       string
	VendorName     string
	ReceiveWindow  uint16
}

// ServerTunnel is the protocol state for one server-side tunnel. The caller
// supplies accepted messages from ControlChannel and queues returned replies
// back through that channel.
type ServerTunnel struct {
	State         TunnelState
	LocalTunnelID uint16
	PeerTunnelID  uint16
	HostName      string
	VendorName    string
	ReceiveWindow uint16
	nextSessionID uint16
	sessions      map[uint16]*Session
}

func NewServerTunnel(config ServerTunnelConfig) *ServerTunnel {
	first := config.FirstSessionID
	if first == 0 {
		first = 1
	}
	window := config.ReceiveWindow
	if window == 0 {
		window = 4
	}
	return &ServerTunnel{State: TunnelIdle, LocalTunnelID: config.LocalTunnelID, HostName: config.HostName, VendorName: config.VendorName, ReceiveWindow: window, nextSessionID: first, sessions: make(map[uint16]*Session)}
}

func (t *ServerTunnel) Handle(message ControlMessage) (*ControlMessage, error) {
	switch message.Type {
	case SCCRQ:
		return t.handleSCCRQ(message)
	case SCCCN:
		if t.State != TunnelWaitConnect || message.TunnelID != t.LocalTunnelID || message.SessionID != 0 {
			return nil, t.unexpected(message)
		}
		t.State = TunnelEstablished
		return nil, nil
	case ICRQ:
		return t.handleICRQ(message)
	case ICCN:
		if t.State != TunnelEstablished || message.TunnelID != t.LocalTunnelID {
			return nil, t.unexpected(message)
		}
		session, ok := t.sessions[message.SessionID]
		if !ok {
			return nil, ErrUnknownSession
		}
		if session.State != SessionWaitConnect {
			return nil, t.unexpected(message)
		}
		session.State = SessionEstablished
		return nil, nil
	case CDN:
		if _, ok := t.sessions[message.SessionID]; !ok {
			return nil, ErrUnknownSession
		}
		delete(t.sessions, message.SessionID)
		return nil, nil
	case StopCCN:
		if t.State == TunnelIdle || message.TunnelID != t.LocalTunnelID {
			return nil, t.unexpected(message)
		}
		t.State = TunnelClosed
		clear(t.sessions)
		return nil, nil
	case Hello:
		if t.State != TunnelEstablished {
			return nil, t.unexpected(message)
		}
		return nil, nil
	default:
		return nil, t.unexpected(message)
	}
}

func (t *ServerTunnel) Session(localID uint16) (Session, bool) {
	session, ok := t.sessions[localID]
	if !ok {
		return Session{}, false
	}
	return *session, true
}

func (t *ServerTunnel) SessionCount() int { return len(t.sessions) }

func (t *ServerTunnel) RemoveSession(localID uint16) { delete(t.sessions, localID) }

func (t *ServerTunnel) handleSCCRQ(message ControlMessage) (*ControlMessage, error) {
	if t.State != TunnelIdle || message.TunnelID != 0 || message.SessionID != 0 {
		return nil, t.unexpected(message)
	}
	peerID, err := requiredUint16(message, AttrAssignedTunnelID)
	if err != nil {
		return nil, err
	}
	version, err := requiredUint16(message, AttrProtocolVersion)
	if err != nil {
		return nil, err
	}
	if version != 0x0100 {
		return nil, fmt.Errorf("%w: protocol version %#04x", ErrInvalidAttribute, version)
	}
	if peerID == 0 {
		return nil, fmt.Errorf("%w: zero assigned tunnel ID", ErrInvalidAttribute)
	}
	if _, err := requiredUint32(message, AttrFramingCap); err != nil {
		return nil, err
	}
	if _, ok := message.Find(AttrHostName); !ok {
		return nil, fmt.Errorf("%w: AVP %d", ErrMissingAttribute, AttrHostName)
	}
	t.PeerTunnelID = peerID
	t.State = TunnelWaitConnect
	return &ControlMessage{Type: SCCRP, AVPs: []AVP{
		Uint16AVP(AttrProtocolVersion, 0x0100, true),
		Uint32AVP(AttrFramingCap, 3, true),
		Uint32AVP(AttrBearerCap, 3, true),
		StringAVP(AttrHostName, t.HostName, true),
		StringAVP(AttrVendorName, t.VendorName, false),
		Uint16AVP(AttrAssignedTunnelID, t.LocalTunnelID, true),
		Uint16AVP(AttrReceiveWindowSize, t.ReceiveWindow, true),
	}}, nil
}

func (t *ServerTunnel) handleICRQ(message ControlMessage) (*ControlMessage, error) {
	if t.State != TunnelEstablished || message.TunnelID != t.LocalTunnelID || message.SessionID != 0 {
		return nil, t.unexpected(message)
	}
	peerID, err := requiredUint16(message, AttrAssignedSessionID)
	if err != nil {
		return nil, err
	}
	if peerID == 0 {
		return nil, fmt.Errorf("%w: zero assigned session ID", ErrInvalidAttribute)
	}
	if _, err := requiredUint32(message, AttrCallSerialNumber); err != nil {
		return nil, err
	}
	localID := t.allocateSessionID()
	t.sessions[localID] = &Session{LocalID: localID, PeerID: peerID, State: SessionWaitConnect}
	return &ControlMessage{Type: ICRP, SessionID: peerID, AVPs: []AVP{Uint16AVP(AttrAssignedSessionID, localID, true)}}, nil
}

func (t *ServerTunnel) allocateSessionID() uint16 {
	for {
		id := t.nextSessionID
		t.nextSessionID++
		if id != 0 {
			if _, used := t.sessions[id]; !used {
				return id
			}
		}
	}
}

func requiredUint16(message ControlMessage, attribute AttributeType) (uint16, error) {
	avp, ok := message.Find(attribute)
	if !ok {
		return 0, fmt.Errorf("%w: AVP %d", ErrMissingAttribute, attribute)
	}
	return avp.Uint16()
}

func requiredUint32(message ControlMessage, attribute AttributeType) (uint32, error) {
	avp, ok := message.Find(attribute)
	if !ok {
		return 0, fmt.Errorf("%w: AVP %d", ErrMissingAttribute, attribute)
	}
	return avp.Uint32()
}

func (t *ServerTunnel) unexpected(message ControlMessage) error {
	return fmt.Errorf("%w: type %d in tunnel state %d", ErrUnexpectedMessage, message.Type, t.State)
}

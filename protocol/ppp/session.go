package ppp

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

type Phase uint8

const (
	PhaseLCP Phase = iota
	PhaseAuthenticate
	PhaseIPCP
	PhaseOpen
	PhaseClosed
)

var (
	ErrUnexpectedProtocol = errors.New("ppp: protocol is not valid in the current phase")
	ErrInvalidIPv4        = errors.New("ppp: invalid IPv4 packet")
	ErrSourceAddress      = errors.New("ppp: unexpected client source address")
)

type Authenticator func(username, password string) bool

func StaticCredentials(username, password string) Authenticator {
	return func(gotUser, gotPassword string) bool {
		return subtle.ConstantTimeCompare([]byte(username), []byte(gotUser)) == 1 && subtle.ConstantTimeCompare([]byte(password), []byte(gotPassword)) == 1
	}
}

type SessionConfig struct {
	ServerAddress netip.Addr
	ClientAddress netip.Addr
	PrimaryDNS    netip.Addr
	SecondaryDNS  netip.Addr
	Authenticate  Authenticator
}

type SessionResult struct {
	Frames []Frame
	IPv4   []byte
}

type Session struct {
	config          SessionConfig
	Phase           Phase
	lcpPeerAcked    bool
	lcpLocalAcked   bool
	ipcpPeerAcked   bool
	ipcpLocalAcked  bool
	lcpRequest      []byte
	ipcpRequestData []byte
}

func NewSession(config SessionConfig) (*Session, error) {
	if !config.ServerAddress.Is4() || !config.ClientAddress.Is4() {
		return nil, errors.New("ppp: server and client IPv4 addresses are required")
	}
	if config.Authenticate == nil {
		return nil, errors.New("ppp: authenticator is required")
	}
	return &Session{config: config, Phase: PhaseLCP}, nil
}

func (s *Session) Start() ([]Frame, error) {
	data, _ := EncodeOptions(Option{Type: 1, Value: []byte{0x05, 0xdc}}, Option{Type: 3, Value: []byte{0xc0, 0x23}})
	s.lcpRequest = append([]byte(nil), data...)
	return controlFrames(ProtocolLCP, ControlPacket{Code: ConfigureRequest, Identifier: 1, Data: data})
}

func (s *Session) Handle(frame Frame) (SessionResult, error) {
	switch frame.Protocol {
	case ProtocolLCP:
		return s.handleLCP(frame.Payload)
	case ProtocolPAP:
		if s.Phase != PhaseAuthenticate {
			return SessionResult{}, ErrUnexpectedProtocol
		}
		return s.handlePAP(frame.Payload)
	case ProtocolIPCP:
		if s.Phase != PhaseIPCP && s.Phase != PhaseOpen {
			return SessionResult{}, ErrUnexpectedProtocol
		}
		return s.handleIPCP(frame.Payload)
	case ProtocolIPv4:
		if s.Phase != PhaseOpen {
			return SessionResult{}, ErrUnexpectedProtocol
		}
		if err := s.validateIPv4(frame.Payload); err != nil {
			return SessionResult{}, err
		}
		return SessionResult{IPv4: append([]byte(nil), frame.Payload...)}, nil
	default:
		return SessionResult{}, fmt.Errorf("%w: %#x", ErrUnexpectedProtocol, frame.Protocol)
	}
}

func (s *Session) handleLCP(payload []byte) (SessionResult, error) {
	packet, err := DecodeControlPacket(payload)
	if err != nil {
		return SessionResult{}, err
	}
	var reply *ControlPacket
	switch packet.Code {
	case ConfigureRequest:
		options, err := DecodeOptions(packet.Data)
		if err != nil {
			return SessionResult{}, err
		}
		var rejected []Option
		for _, option := range options {
			valid := (option.Type == 1 && len(option.Value) == 2) || (option.Type == 5 && len(option.Value) == 4) || ((option.Type == 7 || option.Type == 8) && len(option.Value) == 0)
			if !valid {
				rejected = append(rejected, option)
			}
		}
		if len(rejected) != 0 {
			data, _ := EncodeOptions(rejected...)
			reply = &ControlPacket{Code: ConfigureReject, Identifier: packet.Identifier, Data: data}
		} else {
			s.lcpPeerAcked = true
			reply = &ControlPacket{Code: ConfigureAck, Identifier: packet.Identifier, Data: packet.Data}
		}
	case ConfigureAck:
		if packet.Identifier == 1 && bytes.Equal(packet.Data, s.lcpRequest) {
			s.lcpLocalAcked = true
		}
	case EchoRequest:
		reply = &ControlPacket{Code: EchoReply, Identifier: packet.Identifier, Data: packet.Data}
	case TerminateRequest:
		s.Phase = PhaseClosed
		reply = &ControlPacket{Code: TerminateAck, Identifier: packet.Identifier, Data: packet.Data}
	}
	if s.lcpPeerAcked && s.lcpLocalAcked && s.Phase == PhaseLCP {
		s.Phase = PhaseAuthenticate
	}
	if reply == nil {
		return SessionResult{}, nil
	}
	frames, err := controlFrames(ProtocolLCP, *reply)
	return SessionResult{Frames: frames}, err
}

func (s *Session) handlePAP(payload []byte) (SessionResult, error) {
	packet, err := DecodeControlPacket(payload)
	if err != nil {
		return SessionResult{}, err
	}
	if packet.Code != 1 {
		return SessionResult{}, ErrUnexpectedProtocol
	}
	username, password, err := decodePAPCredentials(packet.Data)
	if err != nil {
		return SessionResult{}, err
	}
	if !s.config.Authenticate(username, password) {
		frames, encodeErr := controlFrames(ProtocolPAP, ControlPacket{Code: 3, Identifier: packet.Identifier, Data: papMessage("authentication failed")})
		if encodeErr != nil {
			return SessionResult{}, encodeErr
		}
		s.Phase = PhaseClosed
		return SessionResult{Frames: frames}, nil
	}
	s.Phase = PhaseIPCP
	ack, err := controlFrames(ProtocolPAP, ControlPacket{Code: 2, Identifier: packet.Identifier, Data: papMessage("welcome")})
	if err != nil {
		return SessionResult{}, err
	}
	request, err := s.ipcpRequest()
	return SessionResult{Frames: append(ack, request...)}, err
}

func (s *Session) ipcpRequest() ([]Frame, error) {
	data, _ := EncodeOptions(Option{Type: 3, Value: s.config.ServerAddress.AsSlice()})
	s.ipcpRequestData = append([]byte(nil), data...)
	return controlFrames(ProtocolIPCP, ControlPacket{Code: ConfigureRequest, Identifier: 1, Data: data})
}

func (s *Session) handleIPCP(payload []byte) (SessionResult, error) {
	packet, err := DecodeControlPacket(payload)
	if err != nil {
		return SessionResult{}, err
	}
	var frames []Frame
	switch packet.Code {
	case ConfigureAck:
		if packet.Identifier == 1 && bytes.Equal(packet.Data, s.ipcpRequestData) {
			s.ipcpLocalAcked = true
		}
	case ConfigureRequest:
		options, err := DecodeOptions(packet.Data)
		if err != nil {
			return SessionResult{}, err
		}
		response := make([]Option, 0, len(options))
		var rejected []Option
		nak := false
		for _, option := range options {
			want, recognized := s.ipcpValue(option.Type)
			if !recognized {
				rejected = append(rejected, option)
				continue
			}
			if len(option.Value) != 4 || string(option.Value) != string(want) {
				nak = true
				response = append(response, Option{Type: option.Type, Value: want})
			} else {
				response = append(response, option)
			}
		}
		code := ConfigureAck
		data := packet.Data
		if len(rejected) != 0 {
			code = ConfigureReject
			data, _ = EncodeOptions(rejected...)
		} else if nak {
			code = ConfigureNak
			data, _ = EncodeOptions(response...)
		} else {
			s.ipcpPeerAcked = true
		}
		frames, err = controlFrames(ProtocolIPCP, ControlPacket{Code: code, Identifier: packet.Identifier, Data: data})
		if err != nil {
			return SessionResult{}, err
		}
	case TerminateRequest:
		s.Phase = PhaseClosed
		frames, err = controlFrames(ProtocolIPCP, ControlPacket{Code: TerminateAck, Identifier: packet.Identifier, Data: packet.Data})
		if err != nil {
			return SessionResult{}, err
		}
	}
	if s.ipcpPeerAcked && s.ipcpLocalAcked && s.Phase == PhaseIPCP {
		s.Phase = PhaseOpen
	}
	return SessionResult{Frames: frames}, nil
}

func (s *Session) ipcpValue(optionType uint8) ([]byte, bool) {
	var address netip.Addr
	switch optionType {
	case 3:
		address = s.config.ClientAddress
	case 129:
		address = s.config.PrimaryDNS
	case 131:
		address = s.config.SecondaryDNS
	default:
		return nil, false
	}
	if !address.Is4() {
		return nil, false
	}
	return address.AsSlice(), true
}

func (s *Session) validateIPv4(packet []byte) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return ErrInvalidIPv4
	}
	headerLength := int(packet[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || totalLength < headerLength || totalLength != len(packet) {
		return ErrInvalidIPv4
	}
	if !bytes.Equal(packet[12:16], s.config.ClientAddress.AsSlice()) {
		return ErrSourceAddress
	}
	return nil
}

func controlFrames(protocol uint16, packet ControlPacket) ([]Frame, error) {
	wire, err := packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return []Frame{{Protocol: protocol, Payload: wire}}, nil
}

func decodePAPCredentials(data []byte) (string, string, error) {
	if len(data) < 2 {
		return "", "", ErrShortControl
	}
	userLength := int(data[0])
	if len(data) < 1+userLength+1 {
		return "", "", ErrShortControl
	}
	username := string(data[1 : 1+userLength])
	data = data[1+userLength:]
	passwordLength := int(data[0])
	if len(data) != 1+passwordLength {
		return "", "", ErrInvalidLength
	}
	return username, string(data[1:]), nil
}

func papMessage(message string) []byte {
	if len(message) > 255 {
		message = message[:255]
	}
	return append([]byte{byte(len(message))}, message...)
}

func IPv4Option(optionType uint8, address netip.Addr) Option {
	return Option{Type: optionType, Value: address.AsSlice()}
}

func ProtocolOption(protocol uint16) Option {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, protocol)
	return Option{Type: 3, Value: b}
}

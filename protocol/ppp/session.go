package ppp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

type Phase uint8

func (p Phase) String() string {
	if int(p) < len(phaseNames) {
		return phaseNames[p]
	}
	return fmt.Sprintf("Phase(%d)", p)
}

var phaseNames = [...]string{"lcp", "authenticate", "ipcp", "open", "closed"}

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

type AuthenticationMethod string

const (
	AuthenticationPAP      AuthenticationMethod = "pap"
	AuthenticationMSCHAPv2 AuthenticationMethod = "mschapv2"
)

type PasswordLookup func(username string) (password string, ok bool)
type Authorizer func(username string) bool

func StaticCredentials(username, password string) Authenticator {
	return func(gotUser, gotPassword string) bool {
		return subtle.ConstantTimeCompare([]byte(username), []byte(gotUser)) == 1 && subtle.ConstantTimeCompare([]byte(password), []byte(gotPassword)) == 1
	}
}

func StaticPassword(username, password string) PasswordLookup {
	return func(gotUsername string) (string, bool) {
		gotUsername = bareUsername(gotUsername)
		if subtle.ConstantTimeCompare([]byte(username), []byte(gotUsername)) != 1 {
			return "", false
		}
		return password, true
	}
}

func Passwords(credentials map[string]string) PasswordLookup {
	return func(username string) (string, bool) {
		password, ok := credentials[bareUsername(username)]
		return password, ok
	}
}

func Credentials(credentials map[string]string) Authenticator {
	return func(username, password string) bool {
		want, ok := credentials[bareUsername(username)]
		return ok && subtle.ConstantTimeCompare([]byte(want), []byte(password)) == 1
	}
}

type SessionConfig struct {
	ServerAddress     netip.Addr
	ClientAddress     netip.Addr
	AuthenticatorName string
	PrimaryDNS        netip.Addr
	SecondaryDNS      netip.Addr
	Authenticate      Authenticator
	Authentication    AuthenticationMethod
	LookupPassword    PasswordLookup
	ChallengeSource   io.Reader
	Authorize         Authorizer
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
	authChallenge   [16]byte
	authIdentifier  uint8
	lcpIdentifier   uint8
	username        string
}

func (s *Session) Authentication() AuthenticationMethod { return s.config.Authentication }
func (s *Session) Username() string                     { return s.username }
func (s *Session) ClientAddress() netip.Addr            { return s.config.ClientAddress }

func NewSession(config SessionConfig) (*Session, error) {
	if !config.ServerAddress.Is4() || !config.ClientAddress.Is4() {
		return nil, errors.New("ppp: server and client IPv4 addresses are required")
	}
	if config.Authentication == "" {
		config.Authentication = AuthenticationPAP
	}
	if config.AuthenticatorName == "" {
		config.AuthenticatorName = "l2tp-go"
	}
	switch config.Authentication {
	case AuthenticationPAP:
		if config.Authenticate == nil {
			return nil, errors.New("ppp: PAP authenticator is required")
		}
	case AuthenticationMSCHAPv2:
		if config.LookupPassword == nil {
			return nil, errors.New("ppp: MS-CHAPv2 password lookup is required")
		}
		if config.ChallengeSource == nil {
			config.ChallengeSource = rand.Reader
		}
	default:
		return nil, fmt.Errorf("ppp: unsupported authentication method %q", config.Authentication)
	}
	return &Session{config: config, Phase: PhaseLCP}, nil
}

func (s *Session) Start() ([]Frame, error) {
	authValue := []byte{0xc0, 0x23}
	if s.config.Authentication == AuthenticationMSCHAPv2 {
		authValue = []byte{0xc2, 0x23, 0x81}
	}
	data, _ := EncodeOptions(Option{Type: 1, Value: []byte{0x05, 0xdc}}, Option{Type: 3, Value: authValue})
	s.lcpRequest = append([]byte(nil), data...)
	s.lcpIdentifier = 1
	return controlFrames(ProtocolLCP, ControlPacket{Code: ConfigureRequest, Identifier: s.lcpIdentifier, Data: data})
}

func (s *Session) Handle(frame Frame) (SessionResult, error) {
	switch frame.Protocol {
	case ProtocolLCP:
		return s.handleLCP(frame.Payload)
	case ProtocolPAP:
		if s.Phase != PhaseAuthenticate || s.config.Authentication != AuthenticationPAP {
			return SessionResult{}, ErrUnexpectedProtocol
		}
		return s.handlePAP(frame.Payload)
	case ProtocolCHAP:
		if s.Phase != PhaseAuthenticate || s.config.Authentication != AuthenticationMSCHAPv2 {
			return SessionResult{}, ErrUnexpectedProtocol
		}
		return s.handleMSCHAPv2(frame.Payload)
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
		if s.Phase == PhaseClosed {
			return SessionResult{}, fmt.Errorf("%w: %#x", ErrUnexpectedProtocol, frame.Protocol)
		}
		return s.rejectProtocol(frame)
	}
}

func (s *Session) rejectProtocol(frame Frame) (SessionResult, error) {
	s.lcpIdentifier++
	data := make([]byte, 2, 2+len(frame.Payload))
	binary.BigEndian.PutUint16(data, frame.Protocol)
	data = append(data, frame.Payload...)
	frames, err := controlFrames(ProtocolLCP, ControlPacket{Code: ProtocolReject, Identifier: s.lcpIdentifier, Data: data})
	if err != nil {
		return SessionResult{}, err
	}
	return SessionResult{Frames: frames}, nil
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
	phaseBefore := s.Phase
	if s.lcpPeerAcked && s.lcpLocalAcked && s.Phase == PhaseLCP {
		s.Phase = PhaseAuthenticate
	}
	var frames []Frame
	if reply != nil {
		encoded, err := controlFrames(ProtocolLCP, *reply)
		if err != nil {
			return SessionResult{}, err
		}
		frames = append(frames, encoded...)
	}
	// Some clients do not start receiving PPP until after they send their
	// first LCP Configure-Request. Repeat our still-unacknowledged request at
	// that point instead of leaving the session permanently in PhaseLCP.
	if packet.Code == ConfigureRequest && !s.lcpLocalAcked {
		encoded, err := controlFrames(ProtocolLCP, ControlPacket{Code: ConfigureRequest, Identifier: 1, Data: s.lcpRequest})
		if err != nil {
			return SessionResult{}, err
		}
		frames = append(frames, encoded...)
	}
	// Windows can send Identification packets and one final LCP request after
	// acknowledging our options. Repeat the active challenge after accepting
	// that request so authentication is not lost during the handoff.
	if packet.Code == ConfigureRequest && phaseBefore == PhaseAuthenticate && s.config.Authentication == AuthenticationMSCHAPv2 {
		challenge, err := s.currentMSCHAPv2Challenge()
		if err != nil {
			return SessionResult{}, err
		}
		frames = append(frames, challenge...)
	}
	if phaseBefore != PhaseAuthenticate && s.Phase == PhaseAuthenticate && s.config.Authentication == AuthenticationMSCHAPv2 {
		challenge, err := s.mschapv2Challenge()
		if err != nil {
			return SessionResult{}, err
		}
		frames = append(frames, challenge...)
	}
	return SessionResult{Frames: frames}, nil
}

func (s *Session) mschapv2Challenge() ([]Frame, error) {
	if _, err := io.ReadFull(s.config.ChallengeSource, s.authChallenge[:]); err != nil {
		return nil, fmt.Errorf("ppp: generate MS-CHAPv2 challenge: %w", err)
	}
	s.authIdentifier++
	return s.currentMSCHAPv2Challenge()
}

func (s *Session) currentMSCHAPv2Challenge() ([]Frame, error) {
	data := append([]byte{16}, s.authChallenge[:]...)
	data = append(data, []byte(s.config.AuthenticatorName)...)
	return controlFrames(ProtocolCHAP, ControlPacket{Code: 1, Identifier: s.authIdentifier, Data: data})
}

func (s *Session) handleMSCHAPv2(payload []byte) (SessionResult, error) {
	packet, err := DecodeControlPacket(payload)
	if err != nil {
		return SessionResult{}, err
	}
	if packet.Code != 2 || packet.Identifier != s.authIdentifier || len(packet.Data) < 50 || packet.Data[0] != 49 {
		return SessionResult{}, ErrUnexpectedProtocol
	}
	value := packet.Data[1:50]
	if !bytes.Equal(value[16:24], make([]byte, 8)) || value[48] != 0 {
		return SessionResult{}, errors.New("ppp: malformed MS-CHAPv2 response")
	}
	username := string(packet.Data[50:])
	password, ok := s.config.LookupPassword(username)
	var peerChallenge [16]byte
	copy(peerChallenge[:], value[:16])
	var response [24]byte
	copy(response[:], value[24:48])
	if !ok || !VerifyNTResponse(response, s.authChallenge[:], peerChallenge[:], username, password) || (s.config.Authorize != nil && !s.config.Authorize(bareUsername(username))) {
		message := fmt.Sprintf("E=691 R=0 C=%X V=3 M=Authentication failed", s.authChallenge)
		frames, encodeErr := controlFrames(ProtocolCHAP, ControlPacket{Code: 4, Identifier: packet.Identifier, Data: []byte(message)})
		if encodeErr != nil {
			return SessionResult{}, encodeErr
		}
		s.Phase = PhaseClosed
		return SessionResult{Frames: frames}, nil
	}
	s.username = bareUsername(username)
	authenticator := GenerateAuthenticatorResponse(password, response, peerChallenge[:], s.authChallenge[:], username)
	s.Phase = PhaseIPCP
	success, err := controlFrames(ProtocolCHAP, ControlPacket{Code: 3, Identifier: packet.Identifier, Data: []byte(authenticator + " M=Welcome")})
	if err != nil {
		return SessionResult{}, err
	}
	request, err := s.ipcpRequest()
	return SessionResult{Frames: append(success, request...)}, err
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
	if !s.config.Authenticate(username, password) || (s.config.Authorize != nil && !s.config.Authorize(bareUsername(username))) {
		frames, encodeErr := controlFrames(ProtocolPAP, ControlPacket{Code: 3, Identifier: packet.Identifier, Data: papMessage("authentication failed")})
		if encodeErr != nil {
			return SessionResult{}, encodeErr
		}
		s.Phase = PhaseClosed
		return SessionResult{Frames: frames}, nil
	}
	s.username = bareUsername(username)
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
		received := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
		return fmt.Errorf("%w: received=%s expected=%s", ErrSourceAddress, received, s.config.ClientAddress)
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

package ppp

import (
	"encoding/hex"
	"testing"
)

func TestMSCHAPv2RFC2759Vector(t *testing.T) {
	auth := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	response := GenerateNTResponse(auth, peer, "User", "clientPass")
	if got, want := hex.EncodeToString(response[:]), "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df"; got != want {
		t.Fatalf("response=%s, want %s", got, want)
	}
	if got, want := GenerateAuthenticatorResponse("clientPass", response, peer, auth, "User"), "S=407A5589115FD0D6209F510FE9C04566932CDA56"; got != want {
		t.Fatalf("authenticator=%s, want %s", got, want)
	}
	if !VerifyNTResponse(response, auth, peer, "DOMAIN\\User", "clientPass") {
		t.Fatal("valid domain-qualified response rejected")
	}
	response[0] ^= 1
	if VerifyNTResponse(response, auth, peer, "User", "clientPass") {
		t.Fatal("modified response accepted")
	}
}

func TestDESKeyRFC2759Vector(t *testing.T) {
	first := expandDESKey(mustHex(t, "FC156AF7EDCD6C"))
	if got, want := hex.EncodeToString(first[:]), "fd0b5b5e7f6e34d9"; got != want {
		t.Fatalf("key=%s, want %s", got, want)
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

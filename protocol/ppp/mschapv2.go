package ppp

import (
	"crypto/des"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"
)

var (
	authenticatorMagic1 = []byte("Magic server to client signing constant")
	authenticatorMagic2 = []byte("Pad to make it do more than one iteration")
)

func GenerateNTResponse(authenticatorChallenge, peerChallenge []byte, username, password string) [24]byte {
	challenge := challengeHash(peerChallenge, authenticatorChallenge, username)
	passwordHash := ntPasswordHash(password)
	return challengeResponse(challenge[:], passwordHash[:])
}

func GenerateAuthenticatorResponse(password string, ntResponse [24]byte, peerChallenge, authenticatorChallenge []byte, username string) string {
	passwordHash := ntPasswordHash(password)
	passwordHashHash := md4Sum(passwordHash[:])
	first := sha1.New()
	first.Write(passwordHashHash[:])
	first.Write(ntResponse[:])
	first.Write(authenticatorMagic1)
	digest := first.Sum(nil)
	challenge := challengeHash(peerChallenge, authenticatorChallenge, username)
	second := sha1.New()
	second.Write(digest)
	second.Write(challenge[:])
	second.Write(authenticatorMagic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(second.Sum(nil)))
}

func VerifyNTResponse(got [24]byte, authenticatorChallenge, peerChallenge []byte, username, password string) bool {
	want := GenerateNTResponse(authenticatorChallenge, peerChallenge, username, password)
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func challengeHash(peerChallenge, authenticatorChallenge []byte, username string) [8]byte {
	username = bareUsername(username)
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authenticatorChallenge)
	h.Write([]byte(username))
	var result [8]byte
	copy(result[:], h.Sum(nil))
	return result
}

func bareUsername(username string) string {
	if slash := strings.LastIndexByte(username, '\\'); slash >= 0 {
		return username[slash+1:]
	}
	return username
}

func ntPasswordHash(password string) [16]byte {
	encoded := utf16.Encode([]rune(password))
	buffer := make([]byte, len(encoded)*2)
	for i, value := range encoded {
		binary.LittleEndian.PutUint16(buffer[i*2:], value)
	}
	return md4Sum(buffer)
}

func challengeResponse(challenge, passwordHash []byte) [24]byte {
	var padded [21]byte
	copy(padded[:], passwordHash)
	var response [24]byte
	for i := 0; i < 3; i++ {
		key := expandDESKey(padded[i*7 : i*7+7])
		cipher, _ := des.NewCipher(key[:])
		cipher.Encrypt(response[i*8:i*8+8], challenge)
	}
	return response
}

func expandDESKey(raw []byte) [8]byte {
	key := [8]byte{
		raw[0] & 0xfe,
		(raw[0]<<7 | raw[1]>>1) & 0xfe,
		(raw[1]<<6 | raw[2]>>2) & 0xfe,
		(raw[2]<<5 | raw[3]>>3) & 0xfe,
		(raw[3]<<4 | raw[4]>>4) & 0xfe,
		(raw[4]<<3 | raw[5]>>5) & 0xfe,
		(raw[5]<<2 | raw[6]>>6) & 0xfe,
		(raw[6] << 1) & 0xfe,
	}
	for i := range key {
		key[i] |= byte(1 ^ (bitsSet(key[i]) & 1))
	}
	return key
}

func bitsSet(value byte) byte {
	value = value - ((value >> 1) & 0x55)
	value = (value & 0x33) + ((value >> 2) & 0x33)
	return (value + (value >> 4)) & 0x0f
}

// md4Sum is a compact RFC 1320 implementation used only for the NT password
// hash required by MS-CHAPv2.
func md4Sum(message []byte) [16]byte {
	data := append([]byte(nil), message...)
	bitLength := uint64(len(data)) * 8
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0)
	}
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], bitLength)
	data = append(data, length[:]...)
	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	for len(data) != 0 {
		var x [16]uint32
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(data[i*4:])
		}
		aa, bb, cc, dd := a, b, c, d
		for i := 0; i < 16; i++ {
			a, b, c, d = md4Step(a, b, c, d, x[i], []int{3, 7, 11, 19}[i%4], 1, i%4)
		}
		order2 := [...]int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for i, k := range order2 {
			a, b, c, d = md4Step(a, b, c, d, x[k], []int{3, 5, 9, 13}[i%4], 2, i%4)
		}
		order3 := [...]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for i, k := range order3 {
			a, b, c, d = md4Step(a, b, c, d, x[k], []int{3, 9, 11, 15}[i%4], 3, i%4)
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
		data = data[64:]
	}
	var result [16]byte
	binary.LittleEndian.PutUint32(result[0:4], a)
	binary.LittleEndian.PutUint32(result[4:8], b)
	binary.LittleEndian.PutUint32(result[8:12], c)
	binary.LittleEndian.PutUint32(result[12:16], d)
	return result
}

func md4Rotate(value uint32, shift int) uint32 { return value<<shift | value>>(32-shift) }

func md4Step(a, b, c, d, word uint32, shift, round, position int) (uint32, uint32, uint32, uint32) {
	apply := func(value, x, y, z uint32) uint32 {
		var function, constant uint32
		switch round {
		case 1:
			function = (x & y) | (^x & z)
		case 2:
			function, constant = (x&y)|(x&z)|(y&z), 0x5a827999
		case 3:
			function, constant = x^y^z, 0x6ed9eba1
		}
		return md4Rotate(value+function+word+constant, shift)
	}
	switch position {
	case 0:
		a = apply(a, b, c, d)
	case 1:
		d = apply(d, a, b, c)
	case 2:
		c = apply(c, d, a, b)
	case 3:
		b = apply(b, c, d, a)
	}
	return a, b, c, d
}

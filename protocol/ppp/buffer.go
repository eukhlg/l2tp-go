package ppp

import (
	"encoding/binary"
	"fmt"
)

type HeaderBuffer interface{ Prepend(int) ([]byte, error) }

// PrependFrame adds an uncompressed PPP header to exclusively owned storage.
func PrependFrame(buffer HeaderBuffer, protocol uint16) error {
	if !validProtocol(protocol) {
		return fmt.Errorf("ppp: invalid protocol %#x", protocol)
	}
	header, err := buffer.Prepend(4)
	if err != nil {
		return err
	}
	header[0], header[1] = Address, Control
	binary.BigEndian.PutUint16(header[2:4], protocol)
	return nil
}

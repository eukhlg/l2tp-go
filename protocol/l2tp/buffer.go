package l2tp

import "encoding/binary"

type HeaderBuffer interface {
	Prepend(int) ([]byte, error)
	Len() int
}

// PrependData adds the unsequenced data header used by the server. Ownership
// remains with the caller, including on failure.
func PrependData(buffer HeaderBuffer, tunnelID, sessionID uint16) error {
	if buffer.Len() > 65535-6 {
		return ErrInvalidPacket
	}
	header, err := buffer.Prepend(6)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(header[:2], version2)
	binary.BigEndian.PutUint16(header[2:4], tunnelID)
	binary.BigEndian.PutUint16(header[4:6], sessionID)
	return nil
}

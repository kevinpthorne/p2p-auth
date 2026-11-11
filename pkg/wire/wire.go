package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

const (
	MaxProtoMsgSize = 4 * 1024 * 1024 // 4 MiB max wire message
	ProtocolAdopt   = "/p2p-auth/adopt/1.0.0"
	ProtocolEnroll  = "/p2p-auth/enroll/1.0.0"
	ProtocolSync    = "/p2p-auth/sync/1.0.0"
	ProtocolVerify  = "/p2p-auth/verify/1.0.0"
	TopicEpoch      = "/p2p-auth/epoch/1.0.0"
	TopicReceipts   = "/p2p-auth/receipts/1.0.0"
)

// WriteMsg writes a 4-byte big-endian length-prefixed protobuf message to w.
func WriteMsg(w io.Writer, msg proto.Message) error {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling proto message: %w", err)
	}
	if len(payload) > MaxProtoMsgSize {
		return fmt.Errorf("proto message size %d exceeds max %d", len(payload), MaxProtoMsgSize)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("writing message length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("writing message payload: %w", err)
	}
	return nil
}

// ReadMsg reads a 4-byte big-endian length-prefixed protobuf message from r into msg.
func ReadMsg(r io.Reader, msg proto.Message) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > MaxProtoMsgSize {
		return fmt.Errorf("incoming message length %d exceeds max %d", length, MaxProtoMsgSize)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("reading message payload: %w", err)
	}
	if err := proto.Unmarshal(payload, msg); err != nil {
		return fmt.Errorf("unmarshaling proto message: %w", err)
	}
	return nil
}

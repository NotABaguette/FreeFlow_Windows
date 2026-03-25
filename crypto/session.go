package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// ClientSession represents an established FreeFlow session on the client side.
type ClientSession struct {
	ID        [8]byte
	Key       [32]byte
	LastSeqNo uint32
	mu        sync.Mutex
}

// NextSeqNo increments and returns the next sequence number.
func (s *ClientSession) NextSeqNo() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeqNo++
	return s.LastSeqNo
}

// Token computes the rotating HMAC-SHA256 session token for a sequence number.
// token = HMAC-SHA256(session_key, uint32be(seqno))[0:4]
func (s *ClientSession) Token(seqNo uint32) [4]byte {
	return ComputeSessionToken(s.Key, seqNo)
}

// ComputeSessionToken generates the rotating per-query session token.
func ComputeSessionToken(sessionKey [32]byte, seqNo uint32) [4]byte {
	mac := hmac.New(sha256.New, sessionKey[:])
	seqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(seqBytes, seqNo)
	mac.Write(seqBytes)
	sum := mac.Sum(nil)

	var token [4]byte
	copy(token[:], sum[:4])
	return token
}

// DeriveSessionKey derives a 32-byte session key from a shared secret using HKDF.
// HKDF-SHA256, salt=nil, info="freeflow-v2-session", output=32 bytes.
func DeriveSessionKey(sharedSecret [32]byte) ([32]byte, error) {
	info := []byte("freeflow-v2-session")
	reader := hkdf.New(sha256.New, sharedSecret[:], nil, info)

	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("HKDF derivation: %w", err)
	}
	return key, nil
}

// DeriveHelloMask computes the 8-byte XOR mask for HELLO_COMPLETE.
// HMAC-SHA256(session_key, "freeflow-hello-complete")[0:8]
func DeriveHelloMask(sessionKey [32]byte) [8]byte {
	mac := hmac.New(sha256.New, sessionKey[:])
	mac.Write([]byte("freeflow-hello-complete"))
	sum := mac.Sum(nil)
	var mask [8]byte
	copy(mask[:], sum[:8])
	return mask
}

// DecodeHelloComplete extracts the session ID from a HELLO_COMPLETE response
// by XORing with the derived mask.
func DecodeHelloComplete(response []byte, sessionKey [32]byte) ([8]byte, error) {
	if len(response) < 8 {
		return [8]byte{}, fmt.Errorf("HELLO_COMPLETE response too short: %d bytes", len(response))
	}
	mask := DeriveHelloMask(sessionKey)
	var sessionID [8]byte
	for i := 0; i < 8; i++ {
		sessionID[i] = response[i] ^ mask[i]
	}
	return sessionID, nil
}

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DeriveE2EKey derives a symmetric key for E2E encryption between two users.
// Uses ECDH(myPriv, theirPub) -> HKDF-SHA256 with info="freeflow-e2e-v1".
func DeriveE2EKey(myPriv [32]byte, theirPub [32]byte) ([32]byte, error) {
	shared, err := ComputeSharedSecret(myPriv, theirPub)
	if err != nil {
		return [32]byte{}, fmt.Errorf("E2E ECDH: %w", err)
	}

	info := []byte("freeflow-e2e-v1")
	reader := hkdf.New(sha256.New, shared[:], nil, info)

	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("E2E HKDF: %w", err)
	}
	return key, nil
}

// E2EEncrypt encrypts plaintext using ChaCha20-Poly1305 with a random nonce.
// Returns nonce(12) || ciphertext || tag(16).
func E2EEncrypt(e2eKey [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(e2eKey[:])
	if err != nil {
		return nil, fmt.Errorf("creating AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// E2EDecrypt decrypts a nonce(12)||ciphertext||tag(16) blob.
func E2EDecrypt(e2eKey [32]byte, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(e2eKey[:])
	if err != nil {
		return nil, fmt.Errorf("creating AEAD: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(blob))
	}

	nonce := blob[:nonceSize]
	ct := blob[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("E2E decryption failed: %w", err)
	}

	return plaintext, nil
}

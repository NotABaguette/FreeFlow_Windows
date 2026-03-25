package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyPair holds an X25519 key pair for Diffie-Hellman key agreement.
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateX25519KeyPair generates a new X25519 key pair with proper clamping.
func GenerateX25519KeyPair() (*KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("generating X25519 private key: %w", err)
	}

	// Clamp private key per X25519 spec
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("computing X25519 public key: %w", err)
	}

	kp := &KeyPair{}
	copy(kp.PrivateKey[:], priv[:])
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// ComputeSharedSecret performs X25519 ECDH key agreement.
func ComputeSharedSecret(privateKey [32]byte, peerPublicKey [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("X25519 ECDH: %w", err)
	}

	var result [32]byte
	copy(result[:], shared)
	return result, nil
}

// Fingerprint computes SHA-256(pubkey)[0:8] as 16 hex chars.
func Fingerprint(pubkey [32]byte) string {
	hash := sha256.Sum256(pubkey[:])
	return hex.EncodeToString(hash[:8])
}

// FingerprintBytes computes SHA-256(pubkey)[0:8] as raw bytes.
func FingerprintBytes(pubkey [32]byte) [8]byte {
	hash := sha256.Sum256(pubkey[:])
	var fp [8]byte
	copy(fp[:], hash[:8])
	return fp
}

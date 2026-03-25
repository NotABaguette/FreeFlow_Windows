package identity

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	ffcrypto "freeflow-windows/crypto"
)

// Identity represents the user's persistent identity.
type Identity struct {
	DisplayName string   `json:"display_name"`
	PrivateKey  [32]byte `json:"-"`
	PublicKey   [32]byte `json:"public_key_bytes"`
	PrivKeyHex  string   `json:"private_key"` // stored encrypted at rest
	PubKeyHex   string   `json:"public_key"`
}

// NewIdentity creates a new identity with X25519 keys.
func NewIdentity(name string) (*Identity, error) {
	kp, err := ffcrypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}
	id := &Identity{
		DisplayName: name,
		PrivateKey:  kp.PrivateKey,
		PublicKey:   kp.PublicKey,
		PrivKeyHex:  hex.EncodeToString(kp.PrivateKey[:]),
		PubKeyHex:   hex.EncodeToString(kp.PublicKey[:]),
	}
	return id, nil
}

// FingerprintHex returns the 16-char hex fingerprint.
func (id *Identity) FingerprintHex() string {
	return ffcrypto.Fingerprint(id.PublicKey)
}

// FingerprintBytes returns the 8-byte fingerprint.
func (id *Identity) FingerprintBytes() [8]byte {
	return ffcrypto.FingerprintBytes(id.PublicKey)
}

// LoadKeys restores raw key bytes from hex strings.
func (id *Identity) LoadKeys() error {
	privBytes, err := hex.DecodeString(id.PrivKeyHex)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid private key hex")
	}
	pubBytes, err := hex.DecodeString(id.PubKeyHex)
	if err != nil || len(pubBytes) != 32 {
		return fmt.Errorf("invalid public key hex")
	}
	copy(id.PrivateKey[:], privBytes)
	copy(id.PublicKey[:], pubBytes)
	return nil
}

// Contact represents a known contact.
type Contact struct {
	DisplayName string   `json:"display_name"`
	PublicKey   [32]byte `json:"-"`
	PubKeyHex  string   `json:"public_key"`
}

// FingerprintHex returns the 16-char hex fingerprint.
func (c *Contact) FingerprintHex() string {
	return ffcrypto.Fingerprint(c.PublicKey)
}

// FingerprintBytes returns the 8-byte fingerprint.
func (c *Contact) FingerprintBytes() [8]byte {
	return ffcrypto.FingerprintBytes(c.PublicKey)
}

// LoadKey restores raw key bytes from hex string.
func (c *Contact) LoadKey() error {
	pubBytes, err := hex.DecodeString(c.PubKeyHex)
	if err != nil || len(pubBytes) != 32 {
		return fmt.Errorf("invalid public key hex: need 64 hex chars (32 bytes)")
	}
	copy(c.PublicKey[:], pubBytes)
	return nil
}

// NewContact creates a contact from a name and hex public key.
func NewContact(name, pubKeyHex string) (*Contact, error) {
	c := &Contact{
		DisplayName: name,
		PubKeyHex:   pubKeyHex,
	}
	if err := c.LoadKey(); err != nil {
		return nil, err
	}
	return c, nil
}

// ContactStore manages the contact list.
type ContactStore struct {
	contacts []*Contact
	mu       sync.RWMutex
}

// NewContactStore creates an empty contact store.
func NewContactStore() *ContactStore {
	return &ContactStore{}
}

// Add adds a contact to the store.
func (cs *ContactStore) Add(c *Contact) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	// Check for duplicate
	for _, existing := range cs.contacts {
		if existing.PubKeyHex == c.PubKeyHex {
			return
		}
	}
	cs.contacts = append(cs.contacts, c)
}

// Remove removes a contact by fingerprint.
func (cs *ContactStore) Remove(fp string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for i, c := range cs.contacts {
		if c.FingerprintHex() == fp {
			cs.contacts = append(cs.contacts[:i], cs.contacts[i+1:]...)
			return
		}
	}
}

// List returns all contacts.
func (cs *ContactStore) List() []*Contact {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	result := make([]*Contact, len(cs.contacts))
	copy(result, cs.contacts)
	return result
}

// FindByFingerprint finds a contact by fingerprint hex.
func (cs *ContactStore) FindByFingerprint(fp string) *Contact {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	for _, c := range cs.contacts {
		if c.FingerprintHex() == fp {
			return c
		}
	}
	return nil
}

// FindByFingerprintBytes finds a contact by raw 8-byte fingerprint.
func (cs *ContactStore) FindByFingerprintBytes(fp [8]byte) *Contact {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	fpHex := hex.EncodeToString(fp[:])
	for _, c := range cs.contacts {
		if c.FingerprintHex() == fpHex {
			return c
		}
	}
	return nil
}

// Save persists contacts to disk.
func (cs *ContactStore) Save(dir string) error {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	data, err := json.MarshalIndent(cs.contacts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "contacts.json"), data, 0600)
}

// Load reads contacts from disk.
func (cs *ContactStore) Load(dir string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(dir, "contacts.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var contacts []*Contact
	if err := json.Unmarshal(data, &contacts); err != nil {
		return err
	}
	for _, c := range contacts {
		if err := c.LoadKey(); err != nil {
			continue
		}
	}
	cs.contacts = contacts
	return nil
}

// SaveIdentity saves an identity to disk.
func SaveIdentity(id *Identity, dir string) error {
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "identity.json"), data, 0600)
}

// LoadIdentity loads an identity from disk.
func LoadIdentity(dir string) (*Identity, error) {
	data, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, err
	}
	if err := id.LoadKeys(); err != nil {
		return nil, err
	}
	return &id, nil
}

package data

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MessageDirection indicates sent or received.
type MessageDirection int

const (
	DirSent     MessageDirection = 0
	DirReceived MessageDirection = 1
)

// MessageStatus indicates delivery state.
type MessageStatus int

const (
	StatusSending   MessageStatus = 0
	StatusSent      MessageStatus = 1
	StatusDelivered MessageStatus = 2
	StatusFailed    MessageStatus = 3
)

// ChatMessage represents a single message in a conversation.
type ChatMessage struct {
	ID        string           `json:"id"`
	Text      string           `json:"text"`
	Direction MessageDirection `json:"direction"`
	Status    MessageStatus    `json:"status"`
	Timestamp time.Time        `json:"timestamp"`
}

// Bulletin represents a signed broadcast from the Oracle.
type Bulletin struct {
	ID           uint16    `json:"id"`
	Content      string    `json:"content"`
	Verified     bool      `json:"verified"`
	SignatureHex string    `json:"signature_hex"`
	Timestamp    time.Time `json:"timestamp"`
}

// Settings holds persistent app configuration.
type Settings struct {
	OracleDomain    string  `json:"oracle_domain"`
	OraclePubKeyHex string  `json:"oracle_pubkey_hex"`
	BootstrapSeed   string  `json:"bootstrap_seed"`
	Resolver        string  `json:"resolver"`
	QueryEncoding   string  `json:"query_encoding"`
	UseRelay        bool    `json:"use_relay"`
	RelayURL        string  `json:"relay_url"`
	RelayAPIKey     string  `json:"relay_api_key"`
	RelayInsecure   bool    `json:"relay_insecure"`
	DevMode              bool    `json:"dev_mode"`
	QueryDelay           float64 `json:"query_delay"`
	SkipAutoTune         bool    `json:"skip_auto_tune"`
	ManualDelay          float64 `json:"manual_delay"`
	LoadBalanceStrength  int     `json:"load_balance_strength"`
	CustomResolvers      string  `json:"custom_resolvers"`
}

// DefaultSettings returns sensible defaults.
func DefaultSettings() Settings {
	return Settings{
		OracleDomain:        "cdn-static-eu.net",
		Resolver:            "8.8.8.8",
		QueryEncoding:       "proquint",
		QueryDelay:          0.1,
		ManualDelay:         0.1,
		LoadBalanceStrength: 5,
	}
}

// AppData holds all persistent app state.
type AppData struct {
	Settings      Settings                       `json:"settings"`
	Conversations map[string][]ChatMessage       `json:"conversations"` // keyed by contact fingerprint
	Bulletins     []Bulletin                     `json:"bulletins"`
	UnreadCounts  map[string]int                 `json:"unread_counts"`
	mu            sync.RWMutex
}

// NewAppData creates a new app data store.
func NewAppData() *AppData {
	return &AppData{
		Settings:      DefaultSettings(),
		Conversations: make(map[string][]ChatMessage),
		Bulletins:     []Bulletin{},
		UnreadCounts:  make(map[string]int),
	}
}

// AddMessage adds a message to a conversation.
func (d *AppData) AddMessage(contactFP string, msg ChatMessage) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Conversations[contactFP] = append(d.Conversations[contactFP], msg)
}

// UpdateMessageStatus updates the status of a sent message.
func (d *AppData) UpdateMessageStatus(msgID string, status MessageStatus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for fp := range d.Conversations {
		for i := range d.Conversations[fp] {
			if d.Conversations[fp][i].ID == msgID {
				d.Conversations[fp][i].Status = status
				return
			}
		}
	}
}

// GetMessages returns all messages for a contact.
func (d *AppData) GetMessages(contactFP string) []ChatMessage {
	d.mu.RLock()
	defer d.mu.RUnlock()
	msgs := d.Conversations[contactFP]
	result := make([]ChatMessage, len(msgs))
	copy(result, msgs)
	return result
}

// IncrementUnread increments the unread count for a contact.
func (d *AppData) IncrementUnread(contactFP string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.UnreadCounts[contactFP]++
}

// ClearUnread clears the unread count for a contact.
func (d *AppData) ClearUnread(contactFP string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.UnreadCounts[contactFP] = 0
}

// AddBulletin adds a bulletin.
func (d *AppData) AddBulletin(b Bulletin) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Avoid duplicates
	for _, existing := range d.Bulletins {
		if existing.ID == b.ID {
			return
		}
	}
	d.Bulletins = append(d.Bulletins, b)
}

// DataDir returns the app data directory.
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".freeflow")
	os.MkdirAll(dir, 0700)
	return dir
}

// Save persists all app data to disk.
func (d *AppData) Save() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	dir := DataDir()
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "appdata.json"), data, 0600)
}

// Load reads all app data from disk.
func (d *AppData) Load() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	dir := DataDir()
	data, err := os.ReadFile(filepath.Join(dir, "appdata.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, d)
}

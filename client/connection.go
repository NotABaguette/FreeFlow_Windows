package client

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	ffcrypto "freeflow-windows/crypto"
	"freeflow-windows/identity"
	"freeflow-windows/protocol"
)

// ConnectionState represents the connection lifecycle.
type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateConnected
)

func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "Disconnected"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	default:
		return "Unknown"
	}
}

// QueryEncoding selects how frames are encoded for DNS transport.
type QueryEncoding int

const (
	EncodingProquint QueryEncoding = iota
	EncodingHex
	EncodingLexical
)

func (e QueryEncoding) String() string {
	switch e {
	case EncodingProquint:
		return "proquint"
	case EncodingHex:
		return "hex"
	default:
		return "lexical"
	}
}

// LogEntry represents a connection log entry.
type LogEntry struct {
	Time    time.Time
	Level   string // "info", "warn", "error", "success"
	Message string
}

// QueryLogEntry represents a dev query log entry.
type QueryLogEntry struct {
	Time      time.Time
	Transport string
	Query     string
	Response  string
}

// Connection manages the FreeFlow protocol connection.
type Connection struct {
	Identity       *identity.Identity
	OraclePublicKey [32]byte
	Session        *ffcrypto.ClientSession
	State          ConnectionState
	Registered     bool

	// Config
	Resolver             string
	Domain               string
	Encoding             QueryEncoding
	UseRelay             bool
	RelayURL             string
	RelayAPIKey          string
	RelayInsecure        bool
	QueryDelay           time.Duration
	SkipAutoTune         bool
	ManualDelay          float64
	LoadBalanceStrength  int
	Pool                 *ResolverPool

	// Stats
	QueryCount    int
	PingLatency   time.Duration
	ServerTime    time.Time

	// Logs
	Log      []LogEntry
	QueryLog []QueryLogEntry
	DevMode  bool

	// Callbacks
	OnStateChange func(ConnectionState)
	OnLog         func(LogEntry)
	OnQueryLog    func(QueryLogEntry)

	mu sync.Mutex
}

// NewConnection creates a new connection manager.
func NewConnection(id *identity.Identity, oraclePubKey [32]byte) *Connection {
	pool := NewResolverPool(nil, 5)
	pool.StartHealthCheck(60 * time.Second)

	return &Connection{
		Identity:            id,
		OraclePublicKey:     oraclePubKey,
		State:               StateDisconnected,
		Resolver:            "8.8.8.8",
		Domain:              "cdn-static-eu.net",
		Encoding:            EncodingProquint,
		QueryDelay:          3 * time.Second,
		ManualDelay:         3.0,
		LoadBalanceStrength: 5,
		Pool:                pool,
	}
}

// NewConnectionWithResolvers creates a connection with custom resolver pool settings.
func NewConnectionWithResolvers(id *identity.Identity, oraclePubKey [32]byte, resolvers []string, strength int) *Connection {
	pool := NewResolverPool(resolvers, strength)
	pool.StartHealthCheck(60 * time.Second)

	c := NewConnection(id, oraclePubKey)
	c.Pool = pool
	c.LoadBalanceStrength = strength
	return c
}

// Close stops background goroutines (health checker).
func (c *Connection) Close() {
	if c.Pool != nil {
		c.Pool.StopHealthCheck()
	}
}

func (c *Connection) addLog(level, msg string) {
	entry := LogEntry{Time: time.Now(), Level: level, Message: msg}
	c.mu.Lock()
	c.Log = append(c.Log, entry)
	if len(c.Log) > 500 {
		c.Log = c.Log[len(c.Log)-500:]
	}
	c.mu.Unlock()
	if c.OnLog != nil {
		c.OnLog(entry)
	}
}

func (c *Connection) addQueryLog(transport, query, response string) {
	if !c.DevMode {
		return
	}
	entry := QueryLogEntry{Time: time.Now(), Transport: transport, Query: query, Response: response}
	c.mu.Lock()
	c.QueryLog = append(c.QueryLog, entry)
	if len(c.QueryLog) > 500 {
		c.QueryLog = c.QueryLog[len(c.QueryLog)-500:]
	}
	c.mu.Unlock()
	if c.OnQueryLog != nil {
		c.OnQueryLog(entry)
	}
}

func (c *Connection) setState(s ConnectionState) {
	c.State = s
	if c.OnStateChange != nil {
		c.OnStateChange(s)
	}
}

func (c *Connection) delay() {
	if c.SkipAutoTune {
		time.Sleep(time.Duration(c.ManualDelay * float64(time.Second)))
	} else {
		time.Sleep(c.QueryDelay)
	}
}

// Delay waits the configured inter-query delay. Exported for use in multi-step
// operations like bulletin fragment fetching.
func (c *Connection) Delay() {
	c.delay()
}

func (c *Connection) transport() string {
	if c.UseRelay {
		return "HTTP"
	}
	return fmt.Sprintf("DNS(%s)", c.Encoding)
}

// Ping sends a PING command and returns the server timestamp.
func (c *Connection) Ping() (time.Time, error) {
	start := time.Now()
	frame := protocol.BuildPingFrame()
	c.addQueryLog(c.transport(), "PING cmd=0x07", "sending...")

	resp, err := c.queryOracle(frame)
	if err != nil {
		c.addLog("error", fmt.Sprintf("PING failed: %v", err))
		return time.Time{}, err
	}
	if err := protocol.CheckErrorResponse(resp); err != nil {
		c.addLog("error", fmt.Sprintf("PING error: %v", err))
		return time.Time{}, err
	}

	c.PingLatency = time.Since(start)

	if len(resp) < 4 {
		return time.Time{}, fmt.Errorf("PING response too short: %d bytes", len(resp))
	}
	serverTime := binary.BigEndian.Uint32(resp[0:4])
	t := time.Unix(int64(serverTime), 0)
	c.ServerTime = t

	c.addLog("success", fmt.Sprintf("PONG: server_time=%d latency=%dms", serverTime, c.PingLatency.Milliseconds()))
	c.addQueryLog(c.transport(), "PING cmd=0x07", fmt.Sprintf("PONG server_time=%d", serverTime))
	return t, nil
}

// Connect performs the full HELLO handshake + auto-REGISTER.
func (c *Connection) Connect() error {
	c.setState(StateConnecting)
	c.addLog("info", "Starting HELLO handshake...")

	// Generate ephemeral X25519 keypair
	ephemeral, err := ffcrypto.GenerateX25519KeyPair()
	if err != nil {
		c.setState(StateDisconnected)
		c.addLog("error", fmt.Sprintf("Key generation failed: %v", err))
		return err
	}

	// Random 16-bit hello nonce
	var nonceBuf [2]byte
	rand.Read(nonceBuf[:])
	helloNonce := binary.BigEndian.Uint16(nonceBuf[:])

	pubBytes := ephemeral.PublicKey[:]

	for i := 0; i < 4; i++ {
		chunk := pubBytes[i*8 : (i+1)*8]
		frame := protocol.BuildHelloChunkFrame(i, helloNonce, chunk)

		chunkHex := hex.EncodeToString(chunk)
		c.addQueryLog(c.transport(), fmt.Sprintf("HELLO chunk=%d/4 nonce=%d data=%s", i, helloNonce, chunkHex), "sending...")

		resp, err := c.queryOracle(frame)
		if err != nil {
			c.setState(StateDisconnected)
			c.addLog("error", fmt.Sprintf("HELLO chunk %d failed: %v", i, err))
			return fmt.Errorf("HELLO chunk %d: %w", i, err)
		}
		if err := protocol.CheckErrorResponse(resp); err != nil {
			c.setState(StateDisconnected)
			c.addLog("error", fmt.Sprintf("HELLO error: %v", err))
			return err
		}

		if i == 3 {
			// Process HELLO_COMPLETE
			sharedSecret, err := ffcrypto.ComputeSharedSecret(ephemeral.PrivateKey, c.OraclePublicKey)
			if err != nil {
				c.setState(StateDisconnected)
				return fmt.Errorf("ECDH failed: %w", err)
			}

			sessionKey, err := ffcrypto.DeriveSessionKey(sharedSecret)
			if err != nil {
				c.setState(StateDisconnected)
				return fmt.Errorf("key derivation failed: %w", err)
			}

			sessionID, err := ffcrypto.DecodeHelloComplete(resp, sessionKey)
			if err != nil {
				c.setState(StateDisconnected)
				return fmt.Errorf("HELLO_COMPLETE decode failed: %w", err)
			}

			c.Session = &ffcrypto.ClientSession{
				ID:  sessionID,
				Key: sessionKey,
			}

			sidHex := hex.EncodeToString(sessionID[:])
			c.addLog("success", fmt.Sprintf("Session established: %s", sidHex))
			c.addQueryLog(c.transport(), "HELLO_COMPLETE", fmt.Sprintf("session_id=%s key_derived=32B", sidHex))

			// Auto-REGISTER after HELLO
			c.delay()
			if err := c.Register(); err != nil {
				c.addLog("warn", fmt.Sprintf("Auto-REGISTER failed: %v", err))
				// Don't fail connect, just warn
			}

			c.setState(StateConnected)
		} else {
			c.addQueryLog(c.transport(), fmt.Sprintf("HELLO chunk=%d/4", i), fmt.Sprintf("ACK chunk_idx=%d", i))
			c.delay()
		}
	}

	return nil
}

// Disconnect destroys the session.
func (c *Connection) Disconnect() {
	c.Session = nil
	c.Registered = false
	c.setState(StateDisconnected)
	c.addLog("info", "Disconnected — session destroyed")
}

// Register binds the persistent identity to the session.
// Single 40-byte frame (fragTotal=1), retries up to 3 times.
func (c *Connection) Register() error {
	if c.Session == nil {
		return fmt.Errorf("no session")
	}
	if c.Identity == nil {
		return fmt.Errorf("no identity")
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		seqNo := c.Session.NextSeqNo()
		token := c.Session.Token(seqNo)

		frame := protocol.BuildRegisterFrame(uint8(seqNo&0xFF), token, c.Identity.PublicKey)
		c.addQueryLog(c.transport(), fmt.Sprintf("REGISTER attempt=%d frame=%dB", attempt, len(frame)), "sending...")

		resp, err := c.queryOracle(frame)
		if err != nil {
			lastErr = err
			c.addLog("warn", fmt.Sprintf("REGISTER attempt %d failed: %v", attempt, err))
			if attempt < 3 {
				c.delay()
			}
			continue
		}
		if err := protocol.CheckErrorResponse(resp); err != nil {
			lastErr = err
			c.addLog("warn", fmt.Sprintf("REGISTER attempt %d error: %v", attempt, err))
			if attempt < 3 {
				c.delay()
			}
			continue
		}

		// Verify fingerprint
		if len(resp) >= 8 {
			oracleFP := hex.EncodeToString(resp[:8])
			localFP := c.Identity.FingerprintHex()
			if oracleFP == localFP {
				c.addLog("success", fmt.Sprintf("REGISTER OK -- fingerprint verified: %s", oracleFP))
			} else {
				c.addLog("warn", fmt.Sprintf("REGISTER WARNING -- fingerprint mismatch! Oracle=%s Local=%s", oracleFP, localFP))
			}
		}

		c.Registered = true
		return nil
	}

	return fmt.Errorf("REGISTER failed after 3 attempts: %v", lastErr)
}

// SendMessage sends an E2E encrypted message to a contact.
// Returns the number of fragments sent.
func (c *Connection) SendMessage(text string, contact *identity.Contact) (int, error) {
	if c.Session == nil {
		return 0, fmt.Errorf("no session")
	}
	if !c.Registered {
		return 0, fmt.Errorf("cannot send: REGISTER not completed")
	}

	// Derive E2E key
	e2eKey, err := ffcrypto.DeriveE2EKey(c.Identity.PrivateKey, contact.PublicKey)
	if err != nil {
		return 0, fmt.Errorf("E2E key derivation: %w", err)
	}

	// Encrypt
	plaintext := []byte(text)
	ciphertext, err := ffcrypto.E2EEncrypt(e2eKey, plaintext)
	if err != nil {
		return 0, fmt.Errorf("E2E encryption: %w", err)
	}

	// Recipient fingerprint bytes
	recipFP := contact.FingerprintBytes()

	// Fragment ciphertext: 4 bytes per fragment for proquint
	maxCTPerFrag := 4
	if c.Encoding == EncodingHex {
		maxCTPerFrag = 50
	}

	var ctFragments [][]byte
	for i := 0; i < len(ciphertext); i += maxCTPerFrag {
		end := i + maxCTPerFrag
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		ctFragments = append(ctFragments, ciphertext[i:end])
	}
	if len(ctFragments) == 0 {
		ctFragments = append(ctFragments, []byte{})
	}

	recipFPHex := hex.EncodeToString(recipFP[:])

	for i, ctChunk := range ctFragments {
		c.delay()
		seqNo := c.Session.NextSeqNo()
		token := c.Session.Token(seqNo)

		frame := protocol.BuildSendMsgFragment(
			uint8(seqNo&0xFF),
			uint8(i), uint8(len(ctFragments)),
			token,
			recipFP[:], ctChunk,
		)

		c.addQueryLog(c.transport(),
			fmt.Sprintf("SEND_MSG frag=%d/%d to=%s ct=%dB", i+1, len(ctFragments), recipFPHex[:8], len(ctChunk)),
			fmt.Sprintf("sending %dB frame...", len(frame)))

		resp, err := c.queryOracle(frame)
		if err != nil {
			return i, fmt.Errorf("SEND_MSG frag %d: %w", i, err)
		}
		if err := protocol.CheckErrorResponse(resp); err != nil {
			return i, fmt.Errorf("SEND_MSG frag %d: %w", i, err)
		}

		c.addQueryLog(c.transport(), fmt.Sprintf("SEND_MSG frag=%d/%d", i+1, len(ctFragments)), fmt.Sprintf("ACK %dB", len(resp)))
	}

	c.addLog("success", fmt.Sprintf("Sent message (%d fragments) to %s", len(ctFragments), contact.DisplayName))
	return len(ctFragments), nil
}

// PollMessages checks for and retrieves a pending message.
// Returns (plaintext, senderFingerprint, error) or ("", nil, nil) if no messages.
func (c *Connection) PollMessages(contacts *identity.ContactStore) (string, *identity.Contact, error) {
	if c.Session == nil {
		return "", nil, fmt.Errorf("no session")
	}
	if !c.Registered {
		return "", nil, fmt.Errorf("cannot poll: REGISTER not completed")
	}

	// Step 1: CHECK
	c.delay()
	seq1 := c.Session.NextSeqNo()
	token1 := c.Session.Token(seq1)

	checkFrame := protocol.BuildGetMsgFrame(uint8(seq1&0xFF), token1, protocol.GetMsgCHECK)
	c.addQueryLog(c.transport(), "GET_MSG CHECK", "sending...")

	checkResp, err := c.queryOracle(checkFrame)
	if err != nil {
		return "", nil, fmt.Errorf("GET_MSG CHECK: %w", err)
	}
	if err := protocol.CheckErrorResponse(checkResp); err != nil {
		return "", nil, fmt.Errorf("GET_MSG CHECK: %w", err)
	}

	// Response: [0x00,...] = no messages, [0x01, senderFP(4), lenHi, lenLo, 0] = has message
	if len(checkResp) < 1 || checkResp[0] != 0x01 {
		c.addLog("info", "No pending messages")
		return "", nil, nil
	}

	totalLen := 0
	if len(checkResp) >= 7 {
		totalLen = int(checkResp[5])<<8 | int(checkResp[6])
	}
	c.addLog("info", fmt.Sprintf("Message found, totalLen=%dB", totalLen))

	// Step 2: FETCH chunks (8 bytes per response)
	var blob []byte
	chunksNeeded := 1
	if totalLen > 0 {
		chunksNeeded = (totalLen + 7) / 8
	}

	for chunkIdx := 0; chunkIdx < chunksNeeded; chunkIdx++ {
		c.delay()
		seqN := c.Session.NextSeqNo()
		tokenN := c.Session.Token(seqN)

		fetchFrame := protocol.BuildGetMsgFrame(uint8(seqN&0xFF), tokenN, protocol.GetMsgFETCH, uint8(chunkIdx))
		c.addQueryLog(c.transport(), fmt.Sprintf("GET_MSG FETCH chunk=%d", chunkIdx), "sending...")

		fetchResp, err := c.queryOracle(fetchFrame)
		if err != nil {
			return "", nil, fmt.Errorf("GET_MSG FETCH chunk %d: %w", chunkIdx, err)
		}
		if err := protocol.CheckErrorResponse(fetchResp); err != nil {
			return "", nil, fmt.Errorf("GET_MSG FETCH chunk %d: %w", chunkIdx, err)
		}

		blob = append(blob, fetchResp...)
		c.addQueryLog(c.transport(), fmt.Sprintf("GET_MSG FETCH chunk=%d", chunkIdx), fmt.Sprintf("got %dB", len(fetchResp)))
	}

	// Step 3: ACK
	c.delay()
	seqAck := c.Session.NextSeqNo()
	tokenAck := c.Session.Token(seqAck)

	ackFrame := protocol.BuildGetMsgFrame(uint8(seqAck&0xFF), tokenAck, protocol.GetMsgACK)
	c.addQueryLog(c.transport(), "GET_MSG ACK", "sending...")

	_, err = c.queryOracle(ackFrame)
	if err != nil {
		c.addLog("warn", fmt.Sprintf("GET_MSG ACK failed: %v", err))
	}

	// Trim blob to totalLen
	if totalLen > 0 && len(blob) > totalLen {
		blob = blob[:totalLen]
	}

	// Parse blob: [senderFP(8)][ciphertext...]
	if len(blob) <= 8 {
		return "", nil, fmt.Errorf("blob too short: %d bytes", len(blob))
	}
	senderFPBytes := blob[:8]
	ciphertext := blob[8:]

	// Find sender contact
	var senderFP [8]byte
	copy(senderFP[:], senderFPBytes)
	senderContact := contacts.FindByFingerprintBytes(senderFP)
	if senderContact == nil {
		senderHex := hex.EncodeToString(senderFPBytes)
		c.addLog("warn", fmt.Sprintf("Unknown sender fingerprint: %s", senderHex))
		return "", nil, fmt.Errorf("unknown sender: %s", senderHex)
	}

	// Decrypt
	e2eKey, err := ffcrypto.DeriveE2EKey(c.Identity.PrivateKey, senderContact.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("E2E key derivation: %w", err)
	}

	plaintext, err := ffcrypto.E2EDecrypt(e2eKey, ciphertext)
	if err != nil {
		return "", nil, fmt.Errorf("E2E decryption: %w", err)
	}

	text := string(plaintext)
	c.addLog("success", fmt.Sprintf("Received message from %s: %d chars", senderContact.DisplayName, len(text)))
	return text, senderContact, nil
}

// GetBulletin fetches a signed bulletin from the Oracle (fragment 0 / header).
func (c *Connection) GetBulletin(lastSeenID uint16) ([]byte, error) {
	frame := protocol.BuildGetBulletinFrame(lastSeenID)
	c.addQueryLog(c.transport(), fmt.Sprintf("GET_BULLETIN lastID=%d", lastSeenID), "sending...")

	resp, err := c.queryOracle(frame)
	if err != nil {
		return nil, fmt.Errorf("GET_BULLETIN: %w", err)
	}
	if err := protocol.CheckErrorResponse(resp); err != nil {
		return nil, err
	}

	c.addQueryLog(c.transport(), "GET_BULLETIN", fmt.Sprintf("response=%dB", len(resp)))
	return resp, nil
}

// GetBulletinFragment fetches a specific fragment of a bulletin.
// fragIndex=0 returns the header, fragIndex=1..N returns content chunks.
func (c *Connection) GetBulletinFragment(lastSeenID uint16, fragIndex uint8) ([]byte, error) {
	frame := protocol.BuildGetBulletinFragmentFrame(lastSeenID, fragIndex)
	c.addQueryLog(c.transport(), fmt.Sprintf("GET_BULLETIN lastID=%d frag=%d", lastSeenID, fragIndex), "sending...")

	resp, err := c.queryOracle(frame)
	if err != nil {
		return nil, fmt.Errorf("GET_BULLETIN frag %d: %w", fragIndex, err)
	}
	if err := protocol.CheckErrorResponse(resp); err != nil {
		return nil, err
	}

	c.addQueryLog(c.transport(), fmt.Sprintf("GET_BULLETIN frag=%d", fragIndex), fmt.Sprintf("response=%dB", len(resp)))
	return resp, nil
}

// Discover sends a DISCOVER command.
func (c *Connection) Discover() ([]byte, error) {
	frame := protocol.BuildDiscoverFrame()
	c.addQueryLog(c.transport(), "DISCOVER", "sending...")

	resp, err := c.queryOracle(frame)
	if err != nil {
		return nil, fmt.Errorf("DISCOVER: %w", err)
	}
	if err := protocol.CheckErrorResponse(resp); err != nil {
		return nil, err
	}

	c.addLog("info", fmt.Sprintf("DISCOVER response: %dB", len(resp)))
	return resp, nil
}

// CacheTest runs the DNS cache test protocol.
func (c *Connection) CacheTest() (int, bool, error) {
	c.addLog("info", "Starting DNS cache test...")

	testTTLs := []int{0, 1, 2, 3, 5, 10}
	var bestTTL int
	allCached := true

	for _, ttl := range testTTLs {
		var seqBuf [2]byte
		rand.Read(seqBuf[:])
		seq := binary.BigEndian.Uint16(seqBuf[:])

		nonce1 := randomAlpha(6)
		nonce2 := randomAlpha(6)

		qname1 := fmt.Sprintf("_ct.%d.%d.%s.%s", ttl, seq, nonce1, c.Domain)
		c.addQueryLog(c.transport(), fmt.Sprintf("CACHE_TEST TTL=%d q1", ttl), qname1)

		ips1, err := c.dnsQueryAAAA(qname1)
		if err != nil {
			c.addLog("warn", fmt.Sprintf("Cache test TTL=%d query 1 failed: %v", ttl, err))
			continue
		}
		counter1 := extractCounter(ips1)

		waitTime := time.Duration(ttl)*time.Second + 500*time.Millisecond
		if waitTime < time.Second {
			waitTime = time.Second
		}
		time.Sleep(waitTime)

		qname2 := fmt.Sprintf("_ct.%d.%d.%s.%s", ttl, seq, nonce2, c.Domain)
		c.addQueryLog(c.transport(), fmt.Sprintf("CACHE_TEST TTL=%d q2", ttl), qname2)

		ips2, err := c.dnsQueryAAAA(qname2)
		if err != nil {
			continue
		}
		counter2 := extractCounter(ips2)

		cached := counter1 == counter2
		if !cached {
			allCached = false
			bestTTL = ttl
			break
		}

		c.addLog("info", fmt.Sprintf("TTL=%d: c1=%d c2=%d cached=%v", ttl, counter1, counter2, cached))
	}

	if allCached {
		c.QueryDelay = 5 * time.Second
		c.addLog("warn", "Aggressive caching detected -- using 5s delay")
	} else {
		delay := time.Duration(bestTTL+1) * time.Second
		if delay < 2*time.Second {
			delay = 2 * time.Second
		}
		c.QueryDelay = delay
		c.addLog("success", fmt.Sprintf("Optimal: TTL=%d delay=%v", bestTTL, c.QueryDelay))
	}

	return bestTTL, !allCached, nil
}

// queryOracle sends a frame via the configured transport and returns the response payload.
func (c *Connection) queryOracle(frame []byte) ([]byte, error) {
	c.mu.Lock()
	c.QueryCount++
	c.mu.Unlock()

	if c.UseRelay {
		return c.queryViaHTTP(frame)
	}
	return c.queryViaDNS(frame)
}

// queryViaDNS encodes a frame as a DNS AAAA query and extracts the response.
func (c *Connection) queryViaDNS(frame []byte) ([]byte, error) {
	// Generate per-query cache-busting nonce
	nonce := randomHex(8)
	nonceLabel := "q-" + nonce

	var frameLabels string

	switch c.Encoding {
	case EncodingProquint:
		// Ensure even byte length
		f := make([]byte, len(frame))
		copy(f, frame)
		if len(f)%2 != 0 {
			f = append(f, 0x00)
		}
		if len(f) <= protocol.MaxBytesPerLabel {
			frameLabels = protocol.ProquintEncode(f)
		} else {
			// Split across multiple labels
			var labels []string
			for i := 0; i < len(f); i += protocol.MaxBytesPerLabel {
				end := i + protocol.MaxBytesPerLabel
				if end > len(f) {
					end = len(f)
				}
				chunk := f[i:end]
				if len(chunk)%2 != 0 {
					chunk = append(chunk, 0x00)
				}
				labels = append(labels, protocol.ProquintEncode(chunk))
			}
			frameLabels = strings.Join(labels, ".")
		}

	case EncodingHex:
		hexStr := hex.EncodeToString(frame)
		var labels []string
		for i := 0; i < len(hexStr); i += 62 {
			end := i + 62
			if end > len(hexStr) {
				end = len(hexStr)
			}
			labels = append(labels, hexStr[i:end])
		}
		frameLabels = strings.Join(labels, ".")

	default:
		// Fallback to hex
		frameLabels = hex.EncodeToString(frame)
	}

	queryName := fmt.Sprintf("%s.%s.%s", frameLabels, nonceLabel, c.Domain)

	records, err := c.dnsQueryAAAA(queryName)
	if err != nil {
		return nil, err
	}

	payload, err := protocol.DecodeAAAARecords(records)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// queryViaHTTP sends a frame via HTTP relay.
func (c *Connection) queryViaHTTP(frame []byte) ([]byte, error) {
	if c.RelayURL == "" {
		return nil, fmt.Errorf("relay URL not configured")
	}

	url := strings.TrimRight(c.RelayURL, "/") + "/api/query"

	client := &http.Client{Timeout: 15 * time.Second}
	if c.RelayInsecure {
		client.Transport = &http.Transport{
			TLSClientConfig: nil, // accept any cert
		}
	}

	resp, err := client.Post(url, "application/octet-stream", strings.NewReader(string(frame)))
	if err != nil {
		return nil, fmt.Errorf("HTTP relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP relay returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading relay response: %w", err)
	}

	return body, nil
}

// dnsQueryAAAA sends a raw DNS AAAA query using the resolver pool for load
// balancing. On failure, the resolver is marked unhealthy and the next one
// is tried.
func (c *Connection) dnsQueryAAAA(name string) ([][]byte, error) {
	query := buildDNSQuery(name)

	maxAttempts := 3
	if c.Pool != nil && c.Pool.HealthyCount() > 3 {
		maxAttempts = c.Pool.HealthyCount()
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resolver := c.Resolver
		if c.Pool != nil {
			resolver = c.Pool.Next()
		}

		addr := resolver + ":53"
		conn, err := net.DialTimeout("udp", addr, 10*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("DNS dial %s: %w", resolver, err)
			if c.Pool != nil {
				c.Pool.MarkUnhealthy(resolver)
			}
			continue
		}

		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			lastErr = fmt.Errorf("DNS write %s: %w", resolver, err)
			if c.Pool != nil {
				c.Pool.MarkUnhealthy(resolver)
			}
			continue
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = fmt.Errorf("DNS read %s: %w", resolver, err)
			if c.Pool != nil {
				c.Pool.MarkUnhealthy(resolver)
			}
			continue
		}

		records, err := parseAAAAResponse(buf[:n])
		if err != nil {
			lastErr = err
			continue
		}
		return records, nil
	}

	return nil, fmt.Errorf("all resolvers failed: %w", lastErr)
}

// buildDNSQuery builds a raw DNS AAAA query packet.
func buildDNSQuery(name string) []byte {
	var buf [2]byte
	rand.Read(buf[:])
	txid := binary.BigEndian.Uint16(buf[:])

	var packet []byte
	packet = append(packet, byte(txid>>8), byte(txid&0xFF))
	packet = append(packet, 0x01, 0x00) // Flags: recursion desired
	packet = append(packet, 0x00, 0x01) // Questions: 1
	packet = append(packet, 0, 0, 0, 0, 0, 0) // Answer, Auth, Additional: 0

	for _, label := range strings.Split(name, ".") {
		b := []byte(label)
		packet = append(packet, byte(len(b)))
		packet = append(packet, b...)
	}
	packet = append(packet, 0) // root

	packet = append(packet, 0x00, 0x1C) // AAAA type (28)
	packet = append(packet, 0x00, 0x01) // IN class

	return packet
}

// parseAAAAResponse extracts AAAA records from a DNS response packet.
func parseAAAAResponse(data []byte) ([][]byte, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS response too short")
	}

	anCount := int(data[6])<<8 | int(data[7])
	if anCount == 0 {
		return nil, fmt.Errorf("no AAAA records in response")
	}

	pos := 12
	// Skip QNAME
	for pos < len(data) {
		l := int(data[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos += 1 + l
	}
	pos += 4 // QTYPE + QCLASS

	var records [][]byte
	for i := 0; i < anCount && pos+12 <= len(data); i++ {
		// Skip NAME
		if data[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(data) && data[pos] != 0 {
				pos += int(data[pos]) + 1
			}
			pos++
		}

		if pos+10 > len(data) {
			break
		}
		rtype := int(data[pos])<<8 | int(data[pos+1])
		pos += 2 + 2 + 4 // TYPE + CLASS + TTL
		rdLength := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		if rtype == 28 && rdLength == 16 && pos+16 <= len(data) {
			rec := make([]byte, 16)
			copy(rec, data[pos:pos+16])
			records = append(records, rec)
		}
		pos += rdLength
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no AAAA records parsed")
	}
	return records, nil
}

func extractCounter(records [][]byte) uint32 {
	if len(records) == 0 || len(records[0]) < 12 {
		return 0
	}
	ip := records[0]
	return binary.BigEndian.Uint32(ip[8:12])
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func randomAlpha(n int) string {
	const letters = "abcdefghijklmnop"
	b := make([]byte, n)
	for i := range b {
		val, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[val.Int64()]
	}
	return string(b)
}
